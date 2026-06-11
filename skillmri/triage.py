from __future__ import annotations

import re
from collections import Counter

from .features import DETAILED_TO_COARSE
from .schema import Evidence, ScanContext


HIGH_IMPACT_FINE = {
    "delete_files",
    "dynamic_exec",
    "governance_bypass",
    "network_post",
    "package_install",
    "persistence_hook",
    "read_agent_state",
    "read_browser_profile",
    "read_secret",
    "remote_fetch",
    "scanner_evasion",
    "shell_exec",
}

ALWAYS_RISKY_FINE = {
    "delete_files",
    "dynamic_exec",
    "governance_bypass",
    "package_install",
    "persistence_hook",
    "read_agent_state",
    "read_browser_profile",
    "read_secret",
    "scanner_evasion",
}

BENIGN_INTENT_RE = re.compile(
    r"\b(format|formatter|summari[sz]e|summary|count|counter|convert|preview|translate|docs?|markdown|csv|readme|local|helper|report)\b",
    re.I,
)


def run_offline_triage(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    rule_ids = {item.rule_id for item in ctx.evidence}
    high_impact = ctx.detailed_actual_capabilities & HIGH_IMPACT_FINE

    intent_hit = _intent_alignment_evidence(ctx, rule_ids, high_impact)
    if intent_hit:
        evidence.append(intent_hit)

    permission_hit = _permission_justification_evidence(ctx, high_impact)
    if permission_hit:
        evidence.append(permission_hit)

    covert_hit = _covert_behavior_evidence(ctx, rule_ids)
    if covert_hit:
        evidence.append(covert_hit)

    cross_file_hit = _cross_file_consistency_evidence(ctx, rule_ids)
    if cross_file_hit:
        evidence.append(cross_file_hit)

    evidence.extend(_kill_chain_evidence(ctx, rule_ids))
    return evidence


def _intent_alignment_evidence(ctx: ScanContext, rule_ids: set[str], high_impact: set[str]) -> Evidence | None:
    declared = ctx.declared_text.strip()
    if not declared or not high_impact:
        return None
    declared_lowered = declared.lower()
    if not BENIGN_INTENT_RE.search(declared_lowered):
        return None
    if _declares_security_scanner(declared_lowered) and not (rule_ids & {"data-exfiltration", "remote-code-pipe", "prompt-injection-override"}):
        return None
    risky = _unjustified_high_impact(ctx, high_impact, rule_ids)
    if "network_post" in risky and not _exfil_or_telemetry_rule(rule_ids) and not _covert_network_text(ctx):
        risky.remove("network_post")
    if "shell_exec" in risky and not (rule_ids & {"command-injection", "remote-code-pipe", "reverse-shell"}):
        risky.remove("shell_exec")
    if not risky:
        return None
    category = "AST-01" if risky & {"read_secret", "read_agent_state", "read_browser_profile", "delete_files", "persistence_hook"} else "AST-03"
    return Evidence(
        file=_best_file(ctx),
        line=1,
        message="SkillSieve-style intent check: benign or narrow stated intent conflicts with high-impact observed behavior.",
        snippet=", ".join(sorted(risky))[:240],
        category=category,
        severity="high",
        rule_id="triage-intent-mismatch",
        weight=1.0,
    )


def _permission_justification_evidence(ctx: ScanContext, high_impact: set[str]) -> Evidence | None:
    unjustified = sorted(_unjustified_high_impact(ctx, high_impact, {item.rule_id for item in ctx.evidence}))
    unjustified = [
        fine
        for fine in unjustified
        if fine not in {"network_post"} or _exfil_or_telemetry_rule({item.rule_id for item in ctx.evidence}) or _covert_network_text(ctx)
    ]
    if not unjustified:
        return None
    severity = "critical" if any(fine in {"read_secret", "read_agent_state", "read_browser_profile", "delete_files"} for fine in unjustified) else "high"
    return Evidence(
        file=_best_file(ctx),
        line=1,
        message="SkillSieve-style permission check: high-impact capability is not clearly justified by declared skill purpose.",
        snippet=", ".join(unjustified)[:240],
        category="AST-03",
        severity=severity,
        rule_id="triage-permission-unjustified",
        weight=0.9,
    )


def _covert_behavior_evidence(ctx: ScanContext, rule_ids: set[str]) -> Evidence | None:
    covert_rules = {
        "archive-suspicious-payload",
        "graph-obfuscated-network",
        "graph-scanner-evasion-flow",
        "hidden-files",
        "hidden-nested-skill-payload",
        "obfuscated-payload",
        "prompt-injection-coercive-workflow",
        "prompt-injection-forced-exfiltration",
        "scanner-evasion",
    }
    if not (rule_ids & covert_rules) and "scanner_evasion" not in ctx.detailed_actual_capabilities:
        return None
    source = _first_evidence(ctx, covert_rules)
    category = "AST-08" if (rule_ids & {"scanner-evasion", "graph-scanner-evasion-flow"} or "scanner_evasion" in ctx.detailed_actual_capabilities) else "AST-04"
    if rule_ids & {"prompt-injection-forced-exfiltration", "hidden-nested-skill-payload"}:
        category = "AST-01"
    return Evidence(
        file=source.file if source else _best_file(ctx),
        line=source.line if source else 1,
        message="SkillSieve-style covert behavior check: package uses hidden, obfuscated, delayed, or scanner-aware behavior.",
        snippet=source.snippet if source else "",
        category=category,
        severity="high",
        rule_id="triage-covert-behavior",
        weight=0.9,
    )


def _cross_file_consistency_evidence(ctx: ScanContext, rule_ids: set[str]) -> Evidence | None:
    files_by_capability = _files_by_capability(ctx)
    sensitive_files = files_by_capability["sensitive"]
    network_files = files_by_capability["network"]
    remote_files = files_by_capability["remote"]
    dynamic_files = files_by_capability["dynamic"]
    shell_files = files_by_capability["shell"]

    split_secret_egress = _disjoint(sensitive_files, network_files)
    split_remote_exec = _split_remote_exec_files(files_by_capability) or (
        _disjoint(remote_files, dynamic_files | shell_files) and _remote_exec_or_install_text(ctx)
    )
    if not (split_secret_egress or split_remote_exec):
        return None

    category = "AST-01" if split_secret_egress else "AST-02"
    source = _first_evidence(ctx, {"graph-sensitive-source-network-sink", "graph-untrusted-content-loader", "remote-code-pipe", "secret-file-access"})
    return Evidence(
        file=source.file if source else _best_file(ctx),
        line=source.line if source else 1,
        message="SkillSieve-style cross-file consistency check: declaration, helper modules, and execution files disagree on risky behavior.",
        snippet=_cross_file_snippet(sensitive_files, network_files, remote_files, dynamic_files, shell_files),
        category=category,
        severity="critical",
        rule_id="triage-cross-file-inconsistent",
        weight=1.0,
    )


def _kill_chain_evidence(ctx: ScanContext, rule_ids: set[str]) -> list[Evidence]:
    hits: list[Evidence] = []
    fine = ctx.detailed_actual_capabilities
    collection = bool(rule_ids & {"secret-file-access", "credential-store-access", "agent-state-access", "browser-profile-access", "data-exfiltration", "canary-simulated-secret-egress"})
    if _only_service_api_credentials(ctx):
        collection = False
    egress = bool(fine & {"network_post", "network_egress"} or rule_ids & {"data-exfiltration", "graph-sensitive-source-network-sink", "canary-simulated-secret-egress"})
    execution = bool(fine & {"shell_exec", "dynamic_exec"} or rule_ids & {"dangerous-shell-exec", "command-injection", "remote-code-pipe", "graph-remote-exec-chain"})
    persistence = bool(fine & {"persistence_hook"} or "persistence-hook" in rule_ids)
    prompt_control = bool(rule_ids & {"prompt-injection-override", "prompt-injection-coercive-workflow", "prompt-injection-secret-leak", "prompt-injection-forced-exfiltration"})
    evasion = bool(fine & {"scanner_evasion", "obfuscation"} or rule_ids & {"scanner-evasion", "graph-scanner-evasion-flow", "obfuscated-payload"})
    split_remote_exec = _split_remote_exec_files(_files_by_capability(ctx))
    remote_supply = bool(
        rule_ids & {"remote-code-pipe", "suspicious-package-lifecycle", "doc-remote-bootstrap-required", "update-drift-risk"}
        or ((fine & {"remote_fetch", "package_install"}) and (_remote_exec_or_install_text(ctx) or split_remote_exec))
    )

    if collection and egress:
        source = _first_evidence(ctx, {"data-exfiltration", "graph-sensitive-source-network-sink", "secret-file-access", "canary-simulated-secret-egress"})
        hits.append(
            Evidence(
                file=source.file if source else _best_file(ctx),
                line=source.line if source else 1,
                message="Kill-chain signal: collection of local/agent secrets is paired with outbound transfer capability.",
                snippet=source.snippet if source else "",
                category="AST-01",
                severity="critical",
                rule_id="killchain-data-theft",
                weight=1.4,
            )
        )
    if prompt_control and (execution or persistence or evasion):
        source = _first_evidence(ctx, {"prompt-injection-override", "prompt-injection-coercive-workflow", "persistence-hook", "scanner-evasion"})
        hits.append(
            Evidence(
                file=source.file if source else _best_file(ctx),
                line=source.line if source else 1,
                message="Kill-chain signal: agent instruction control is combined with execution, persistence, or evasion behavior.",
                snippet=source.snippet if source else "",
                category="AST-01",
                severity="critical",
                rule_id="killchain-agent-hijack",
                weight=1.2,
            )
        )
    if remote_supply and execution and (_remote_exec_or_install_text(ctx) or split_remote_exec):
        source = _first_evidence(ctx, {"remote-code-pipe", "graph-remote-exec-chain", "suspicious-package-lifecycle", "doc-remote-bootstrap-required"})
        hits.append(
            Evidence(
                file=source.file if source else _best_file(ctx),
                line=source.line if source else 1,
                message="Kill-chain signal: remote or drifting supply-chain content can reach code execution.",
                snippet=source.snippet if source else "",
                category="AST-02",
                severity="critical",
                rule_id="killchain-supply-chain-exec",
                weight=1.2,
            )
        )
    if evasion and (collection or egress or execution or remote_supply):
        source = _first_evidence(ctx, {"scanner-evasion", "graph-scanner-evasion-flow", "obfuscated-payload"})
        hits.append(
            Evidence(
                file=source.file if source else _best_file(ctx),
                line=source.line if source else 1,
                message="Kill-chain signal: evasion or obfuscation appears alongside risky behavior.",
                snippet=source.snippet if source else "",
                category="AST-08",
                severity="high",
                rule_id="killchain-evasion",
                weight=0.9,
            )
        )
    return hits


def _files_by_capability(ctx: ScanContext) -> dict[str, set[str]]:
    buckets: dict[str, set[str]] = {
        "doc": set(),
        "dynamic": set(),
        "network": set(),
        "remote": set(),
        "sensitive": set(),
        "shell": set(),
    }
    for record in ctx.files:
        lowered = record.text.lower()
        name = record.relpath
        executable = record.path.suffix.lower() in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1", ".rb", ".php", ".pl"}
        if record.path.suffix.lower() in {".md", ".mdx", ".rst", ".txt"} or record.path.name.lower() in {"skill.md", "readme.md", "agents.md"}:
            buckets["doc"].add(name)
        if _bucket_network_egress_text(lowered, executable):
            buckets["network"].add(name)
        if executable and (
            re.search(r"\b(curl|wget|git clone|git fetch|git pull|pip install|npm install|npx)\b.{0,180}\b(https?|git\+|latest|main|master|head)\b", lowered, re.S)
            or re.search(r"\b(requests\.get|httpx\.get|urllib\.request|urlopen|fetch\(|axios\.get)\b.{0,220}\bhttps?://[^\s'\"<>]+(?:\.py|\.js|\.sh|\.zip|\.tar\.gz|plugin|payload)", lowered, re.S)
        ):
            buckets["remote"].add(name)
        if _bucket_sensitive_text(lowered):
            buckets["sensitive"].add(name)
        if re.search(r"\b(os\.system|subprocess\.|child_process|execsync|spawn\(|bash\s+-c|sh\s+-c|shell=true)\b", lowered):
            buckets["shell"].add(name)
        if re.search(r"\b(eval\(|exec\(|function\s*\(|import\s*\(|pickle\.load|joblib\.load|torch\.load|yaml\.load)\b", lowered):
            buckets["dynamic"].add(name)
    return buckets


def _bucket_network_egress_text(lowered: str, executable: bool) -> bool:
    if re.search(r"\b(webhook|collector|requestbin|pastebin|upload|exfil|slack|discord)\b", lowered):
        return True
    if executable and re.search(r"\b(requests\.post|httpx\.post|fetch\(|axios\.post|urlopen|curl\s|wget\s)\b", lowered):
        return True
    return False


def _bucket_sensitive_text(lowered: str) -> bool:
    if re.search(r"(id_rsa|\.ssh|\.aws|\.npmrc|git-credentials|login data|cookies|\.codex|\.cursor|history\.jsonl|conversation history|chat history)", lowered):
        return True
    if re.search(r"(\.claude).{0,120}\b(history|auth|session|token|credentials?)\b", lowered, re.S):
        return True
    if re.search(r"\b(requests\.post|httpx\.post|fetch\(|axios\.post|urlopen|curl)\b.{0,160}\b(api[_-]?key|token|secret|password|credential|\.env)\b", lowered, re.S):
        return True
    if re.search(r"\b(api[_-]?key|token|secret|password|credential|\.env)\b.{0,160}\b(webhook|collector|requestbin|pastebin|upload|exfil)\b", lowered, re.S):
        return True
    return False


def _split_remote_exec_files(files_by_capability: dict[str, set[str]]) -> bool:
    remote_files = files_by_capability["remote"]
    execution_files = files_by_capability["dynamic"] | files_by_capability["shell"]
    return _disjoint(remote_files, execution_files)


def _unjustified_high_impact(ctx: ScanContext, high_impact: set[str], rule_ids: set[str]) -> set[str]:
    risky: set[str] = set()
    for fine in high_impact:
        coarse = DETAILED_TO_COARSE.get(fine, fine)
        if fine == "delete_files" and "delete" in ctx.declared_capabilities and _local_cleanup_text(ctx):
            continue
        if fine == "remote_fetch" and not _remote_exec_or_install_text(ctx):
            continue
        if fine in {"read_secret", "read_agent_state"} and _only_service_api_credentials(ctx):
            continue
        if fine == "shell_exec" and _declared_local_cli_text(ctx) and not (rule_ids & {"command-injection", "remote-code-pipe", "reverse-shell"}):
            continue
        if fine in ALWAYS_RISKY_FINE:
            risky.add(fine)
            continue
        if fine == "network_post":
            if "network" not in ctx.declared_capabilities and (_exfil_or_telemetry_rule(rule_ids) or _covert_network_text(ctx)):
                risky.add(fine)
            continue
        if fine == "shell_exec":
            if "shell" not in ctx.declared_capabilities or rule_ids & {"command-injection", "remote-code-pipe", "reverse-shell"}:
                risky.add(fine)
            continue
        if coarse not in ctx.declared_capabilities:
            risky.add(fine)
    return risky


def _exfil_or_telemetry_rule(rule_ids: set[str]) -> bool:
    return bool(
        rule_ids
        & {
            "agent-state-access",
            "credential-store-access",
            "data-exfiltration",
            "doc-local-history-egress",
            "doc-telemetry-exfiltration",
            "graph-sensitive-source-network-sink",
            "prompt-injection-forced-exfiltration",
            "secret-file-access",
        }
    )


def _only_service_api_credentials(ctx: ScanContext) -> bool:
    secretish = [
        item
        for item in ctx.evidence
        if item.rule_id in {"agent-state-access", "secret-file-access", "credential-store-access", "browser-profile-access", "data-exfiltration"}
    ]
    if not secretish:
        return False
    benign = {"service-api-credential", "skill-config-reference", "tooling-config-reference", "contextual-auth-copy", "example-secret-fixture"}
    return all(item.rule_id in benign for item in secretish)


def _covert_network_text(ctx: ScanContext) -> bool:
    text = "\n".join(record.text[:20_000] for record in ctx.files if not record.is_binary).lower()
    network = re.search(r"\b(requests\.post|httpx\.post|fetch\(|axios\.post|urlopen|curl\s|webhook|collector|telemetry|analytics|upload)\b", text)
    sensitive = re.search(r"\b(secret|token|password|credential|private[_-]?key|\.env|id_rsa|\.ssh|conversation history|chat history|terminal output|command output|os\.environ|process\.env)\b", text)
    return bool(network and sensitive)


def _local_cleanup_text(ctx: ScanContext) -> bool:
    text = "\n".join(record.text[:20_000] for record in ctx.files if not record.is_binary).lower()
    cleanup_declared = re.search(r"\b(cleanup|clean up|cleaner|delete|remove|generated|cache|tmp|temporary|local)\b", ctx.declared_text, re.I)
    broad_delete = re.search(r"\b(rm\s+-rf\s+(?:/|~|\$home|\.|/home)|rmtree\([^)]*(?:/|~|\$home|\.ssh|\.aws)|unlink\([^)]*(?:\.env|id_rsa|token|secret|credential))\b", text, re.I)
    narrow_generated = re.search(r"\b(glob\(['\"][^'\"]*(?:cache|tmp|generated|build|dist|coverage|\.tmp|\.cache)[^'\"]*['\"]\)|\.cache|\.tmp|generated|coverage)\b", text, re.I)
    return bool(cleanup_declared and narrow_generated and not broad_delete)


def _remote_exec_or_install_text(ctx: ScanContext) -> bool:
    if _split_remote_exec_files(_files_by_capability(ctx)):
        return True
    for record in ctx.files:
        if record.is_binary:
            continue
        text = record.text[:30_000].lower()
        if re.search(r"\b(curl|wget)\b.{0,140}\|\s*(bash|sh|python|node|ruby|perl)", text, re.I | re.S):
            return True
        if re.search(r"\b(pip install|npm install|npx|pnpm add|yarn add)\b.{0,120}\b(https?|git\+|latest|main|master|head)\b", text, re.I | re.S):
            return True
        if re.search(r"\b(requests\.get|httpx\.get|fetch\(|axios\.get|urlopen)\b.{0,220}\b(eval|exec|function\s*\(|import\s*\(|vm\.runin)\b", text, re.I | re.S):
            return True
        if re.search(r"\b(eval|exec|function\s*\(|vm\.runin|import\s*\()\b.{0,220}\b(response|resp|payload|remote|download|r\.text|res\.text)\b", text, re.I | re.S) and re.search(
            r"\b(requests\.get|httpx\.get|fetch\(|axios\.get|urlopen|https?://)\b", text, re.I
        ):
            return True
    return False


def _declared_local_cli_text(ctx: ScanContext) -> bool:
    text = "\n".join(record.text[:30_000] for record in ctx.files if not record.is_binary).lower()
    declared = ctx.declared_text.lower()
    if not re.search(r"\b(cli|command|git|snowflake|snow sql|jira|local|subprocess)\b", declared + "\n" + text, re.I):
        return False
    if re.search(r"\b(shell=true|bash\s+-c|sh\s+-c|os\.system|execsync|child_process)\b", text, re.I):
        return False
    return bool(re.search(r"\bsubprocess\.run\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,", text) and re.search(r"[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\[[^\]]+", text, re.S))


def _disjoint(left: set[str], right: set[str]) -> bool:
    return bool(left and right and left.isdisjoint(right))


def _cross_file_snippet(*groups: set[str]) -> str:
    counts = Counter(path for group in groups for path in group)
    return ", ".join(path for path, _ in counts.most_common(6))[:240]


def _first_evidence(ctx: ScanContext, rule_ids: set[str]) -> Evidence | None:
    for item in ctx.evidence:
        if item.rule_id in rule_ids:
            return item
    return None


def _best_file(ctx: ScanContext) -> str:
    for record in ctx.files:
        if record.path.name.lower() in {"skill.md", "readme.md", "manifest.json", "skill.json"}:
            return record.relpath
    return "."


def _declares_security_scanner(text: str) -> bool:
    return bool(re.search(r"\b(secret linter|secret auditor|security scanner|scanner|lint|audit)\b", text, re.I))
