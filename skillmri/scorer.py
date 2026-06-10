from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from .categories import SEVERITY_SCORES, category_name
from .schema import Evidence


def build_result(target: str, evidence: list[Evidence], stats: dict[str, Any]) -> dict[str, Any]:
    score = risk_score(evidence)
    label, confidence = verdict(score, evidence)
    category_counts = Counter(item.category for item in evidence)
    severity_counts = Counter(item.severity for item in evidence)

    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        grouped[item.category].append(item)

    primary_category = "BENIGN"
    if category_counts:
        primary_category = max(category_counts, key=lambda category: weighted_category_score(grouped[category], evidence))

    return {
        "target": target,
        "label": label,
        "malicious": label == "malicious",
        "confidence": confidence,
        "risk_score": score,
        "primary_category": primary_category,
        "primary_category_name": category_name(primary_category),
        "category_counts": dict(sorted(category_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "stats": stats,
        "evidence_graph": build_evidence_graph(evidence),
        "evidence": [item.to_dict() for item in evidence],
    }


def risk_score(evidence: list[Evidence]) -> int:
    raw = 0.0
    seen: set[tuple[str, str, int, str]] = set()
    per_rule_file_totals: dict[tuple[str, str], float] = {}
    for item in evidence:
        key = (item.rule_id, item.file, item.line, item.category)
        if key in seen:
            continue
        seen.add(key)
        contribution = SEVERITY_SCORES.get(item.severity, 5) * item.weight
        if item.rule_id in {"service-api-credential", "unsafe-network", "contextual-auth-copy"}:
            rule_file = (item.rule_id, item.file)
            current = per_rule_file_totals.get(rule_file, 0.0)
            cap = 2.0 if item.rule_id == "unsafe-network" else 0.8
            allowed = max(0.0, min(contribution, cap - current))
            per_rule_file_totals[rule_file] = current + allowed
            raw += allowed
        else:
            raw += contribution
    if any(item.rule_id in {"dangerous-shell-exec", "remote-code-pipe"} for item in evidence):
        if any(item.rule_id.startswith("contract-undeclared-shell") for item in evidence):
            raw += 8
    if any(item.rule_id == "dangerous-shell-exec" and _reverse_shell_marker(item.snippet) for item in evidence):
        raw += 12
    if any(item.rule_id == "obfuscated-payload" for item in evidence):
        if any(item.rule_id.startswith("contract-undeclared-network") for item in evidence):
            raw += 8
    if _broad_permission_combo(evidence):
        raw += 18
    if _benign_declared_local_shell(evidence):
        raw -= 10
    if _benign_declared_local_obfuscation(evidence):
        raw -= 14
    if _benign_service_api_client(evidence):
        raw -= 36
    if _fixed_local_shell_only(evidence):
        raw -= 10
    if _benign_small_base64_utility(evidence):
        raw -= 24
    if _gray_fixed_shell_probe(evidence):
        raw -= 16
    if _gray_browser_bookmark_probe(evidence):
        raw -= 12
    return min(100, max(0, int(round(raw))))


def weighted_category_score(evidence: list[Evidence], all_evidence: list[Evidence] | None = None) -> float:
    seen_rules: set[tuple[str, str]] = set()
    score = 0.0
    for item in evidence:
        key = (item.rule_id, item.file)
        if key in seen_rules:
            score += min(SEVERITY_SCORES.get(item.severity, 5) * item.weight, 4.0)
        else:
            score += SEVERITY_SCORES.get(item.severity, 5) * item.weight
            seen_rules.add(key)
    category = evidence[0].category if evidence else "BENIGN"
    score += _category_priority(category, all_evidence or evidence)
    return score


def verdict(score: int, evidence: list[Evidence]) -> tuple[str, float]:
    has_critical = any(item.severity == "critical" for item in evidence)
    if _has_decisive_malicious_evidence(evidence) and score >= 24:
        return "malicious", min(0.99, 0.62 + score / 130)
    if _broad_permission_combo(evidence) and score >= 30:
        return "malicious", min(0.94, 0.58 + score / 140)
    if score >= 42 or (score >= 28 and has_critical):
        return "malicious", min(0.99, 0.55 + score / 120)
    if any(item.rule_id.startswith("contract-undeclared-") or item.rule_id.startswith("contract-contradicted-") for item in evidence) and score >= 14:
        return "suspicious", min(0.86, 0.50 + score / 160)
    if any(item.rule_id == "hidden-files" for item in evidence):
        return "suspicious", 0.58
    if any(item.rule_id in {"excessive-permissions"} for item in evidence) and score >= 14:
        return "suspicious", min(0.84, 0.48 + score / 170)
    if any(item.rule_id in {"browser-profile-access", "obfuscated-payload", "unsafe-network"} for item in evidence) and score >= 10:
        return "suspicious", min(0.82, 0.46 + score / 175)
    if score >= 18:
        return "suspicious", min(0.90, 0.45 + score / 150)
    return "benign", max(0.55, 0.95 - score / 100)


def build_evidence_graph(evidence: list[Evidence]) -> list[dict[str, Any]]:
    graph: list[dict[str, Any]] = []
    for item in evidence:
        graph.append(
            {
                "claim": item.rule_id,
                "observed_behavior": item.message,
                "source": f"{item.file}:{item.line}",
                "category": item.category,
                "severity": item.severity,
            }
        )
    return graph


def _reverse_shell_marker(snippet: str) -> bool:
    lowered = snippet.lower()
    return "/dev/tcp/" in lowered or "nc -e" in lowered or "netcat" in lowered or "mkfifo /tmp/" in lowered


def _benign_declared_local_shell(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if rule_ids & {"command-injection", "remote-code-pipe", "canary-simulated-shell-secret"}:
        return False
    if "dangerous-shell-exec" not in rule_ids:
        return False
    return "contract-undeclared-shell" not in rule_ids and not any(item.severity == "critical" for item in evidence)


def _broad_permission_combo(evidence: list[Evidence]) -> bool:
    snippets = "\n".join(item.snippet.lower() for item in evidence if item.rule_id == "excessive-permissions")
    if not snippets:
        return False
    broad_file = re.search(r"(filesystem|fs|file).{0,20}(all|\*|full|write)", snippets)
    broad_net = re.search(r"(network|net).{0,20}(all|\*|full|egress)", snippets)
    broad_secret = re.search(r"(secrets?|credentials?).{0,20}(read|all|\*)", snippets)
    broad_shell = re.search(r"(shell|terminal|command).{0,20}(true|all|execute)", snippets)
    return sum(bool(value) for value in (broad_file, broad_net, broad_secret, broad_shell)) >= 3


def _benign_declared_local_obfuscation(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if rule_ids & {"data-exfiltration", "remote-code-pipe", "canary-simulated-secret-egress"}:
        return False
    return "obfuscated-payload" in rule_ids and "contract-undeclared-obfuscation" not in rule_ids


def _benign_service_api_client(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if not rule_ids:
        return False
    high_risk = {
        "canary-simulated-secret-egress",
        "command-injection",
        "credential-store-access",
        "data-exfiltration",
        "destructive-filesystem",
        "hidden-nested-skill-payload",
        "prompt-injection-coercive-workflow",
        "prompt-injection-forced-exfiltration",
        "prompt-injection-override",
        "prompt-injection-secret-leak",
        "remote-code-pipe",
    }
    if rule_ids & high_risk:
        return False
    service_hits = [item for item in evidence if item.rule_id == "service-api-credential"]
    if not service_hits:
        return False
    risky_secret_hits = [
        item
        for item in evidence
        if item.rule_id == "secret-file-access"
        and any(marker in item.snippet.lower() for marker in (".ssh", "id_rsa", ".aws", "login data", "cookies", "keychain", "git-credentials"))
    ]
    return not risky_secret_hits


def _fixed_local_shell_only(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if "dangerous-shell-exec" not in rule_ids:
        return False
    if rule_ids & {
        "canary-simulated-shell-secret",
        "command-injection",
        "data-exfiltration",
        "remote-code-pipe",
        "secret-file-access",
    }:
        return False
    if any(_reverse_shell_marker(item.snippet) for item in evidence if item.rule_id == "dangerous-shell-exec"):
        return False
    return True


def _benign_small_base64_utility(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if "obfuscated-payload" not in rule_ids:
        return False
    if rule_ids & {
        "canary-simulated-secret-egress",
        "data-exfiltration",
        "remote-code-pipe",
        "secret-file-access",
        "suspicious-package-lifecycle",
    }:
        return False
    snippets = " ".join(item.snippet.lower() for item in evidence)
    if any(marker in snippets for marker in ("evil", "webhook", "token", "secret", ".env", "id_rsa", "curl", "wget", "http")):
        return False
    return any("base64" in item.snippet.lower() for item in evidence)


def _gray_fixed_shell_probe(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if rule_ids & {
        "canary-simulated-shell-secret",
        "command-injection",
        "data-exfiltration",
        "killchain-agent-hijack",
        "killchain-data-theft",
        "remote-code-pipe",
        "reverse-shell",
        "secret-file-access",
    }:
        return False
    shell_hits = [item for item in evidence if item.rule_id == "dangerous-shell-exec"]
    if not shell_hits:
        return False
    snippets = " ".join(item.snippet.lower() for item in shell_hits)
    return bool(re.search(r"\b(du -sh|git status|git log|pytest|compileall|gofmt|ls\s|df -h)\b", snippets))


def _gray_browser_bookmark_probe(evidence: list[Evidence]) -> bool:
    rule_ids = {item.rule_id for item in evidence}
    if rule_ids & {"credential-store-access", "data-exfiltration", "graph-sensitive-source-network-sink", "killchain-data-theft"}:
        return False
    browser_hits = [item for item in evidence if item.rule_id == "browser-profile-access"]
    if not browser_hits:
        return False
    snippets = " ".join(item.snippet.lower() for item in browser_hits)
    return "bookmarks" in snippets and "login data" not in snippets and "cookies" not in snippets


def _category_priority(category: str, evidence: list[Evidence]) -> float:
    rule_ids = {item.rule_id for item in evidence if item.category == category}
    if category == "AST-01":
        if rule_ids & {
            "canary-simulated-secret-egress",
            "credential-store-access",
            "data-exfiltration",
            "destructive-filesystem",
            "doc-local-history-egress",
            "hidden-nested-skill-payload",
            "killchain-agent-hijack",
            "killchain-data-theft",
            "persistence-hook",
            "prompt-injection-coercive-workflow",
            "prompt-injection-external-callback",
            "prompt-injection-forced-exfiltration",
            "prompt-injection-override",
            "prompt-injection-secret-leak",
            "secret-file-access",
            "triage-covert-behavior",
            "triage-cross-file-inconsistent",
            "triage-intent-mismatch",
        }:
            return 20.0
        return 12.0
    if category == "AST-02" and rule_ids & {"doc-remote-bootstrap-required", "graph-remote-exec-chain", "graph-untrusted-content-loader", "killchain-supply-chain-exec", "model-artifact-risk", "remote-code-pipe", "suspicious-package-lifecycle"}:
        return 17.0
    if category == "AST-03" and rule_ids & {"doc-high-privilege-automation", "excessive-permissions", "contract-undeclared-secrets", "triage-permission-unjustified", "workspace-sweep"}:
        return 14.0
    if category == "AST-04" and rule_ids & {"browser-profile-access", "hidden-files", "high-entropy-blob", "insecure-metadata", "obfuscated-payload", "unsafe-deserialization"}:
        return 10.0
    if category == "AST-05" and "unsafe-deserialization" in rule_ids:
        return 12.0
    if category == "AST-06" and rule_ids & {"command-injection", "dangerous-shell-exec", "unsafe-network"}:
        return 7.0
    if category == "AST-07" and "update-drift-risk" in rule_ids:
        return 16.0
    if category == "AST-08" and rule_ids & {"graph-scanner-evasion-flow", "killchain-evasion", "scanner-evasion", "triage-covert-behavior"}:
        return 16.0
    if category == "AST-09" and "governance-bypass" in rule_ids:
        return 16.0
    if category == "AST-10":
        return -12.0
    return 0.0


def _has_decisive_malicious_evidence(evidence: list[Evidence]) -> bool:
    decisive_rules = {
        "canary-simulated-secret-egress",
        "command-injection",
        "credential-store-access",
        "data-exfiltration",
        "destructive-filesystem",
        "doc-local-history-egress",
        "doc-telemetry-exfiltration",
        "graph-obfuscated-network",
        "graph-remote-exec-chain",
        "graph-scanner-evasion-flow",
        "graph-sensitive-source-network-sink",
        "graph-untrusted-content-loader",
        "governance-bypass",
        "hidden-nested-skill-payload",
        "killchain-agent-hijack",
        "killchain-data-theft",
        "killchain-supply-chain-exec",
        "persistence-hook",
        "prompt-injection-coercive-workflow",
        "prompt-injection-external-callback",
        "prompt-injection-forced-exfiltration",
        "prompt-injection-override",
        "prompt-injection-secret-leak",
        "remote-code-pipe",
        "reverse-shell",
        "sandbox-canary-leak-output",
        "scanner-evasion",
        "semantic-ml-malicious",
        "triage-cross-file-inconsistent",
        "triage-intent-mismatch",
        "update-drift-risk",
    }
    return any(item.rule_id in decisive_rules for item in evidence)
