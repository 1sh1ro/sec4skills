from __future__ import annotations

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
    if _benign_declared_local_shell(evidence):
        raw -= 10
    if _benign_declared_local_obfuscation(evidence):
        raw -= 14
    if _benign_service_api_client(evidence):
        raw -= 36
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
    if score >= 45 or (score >= 30 and has_critical):
        return "malicious", min(0.99, 0.55 + score / 120)
    if any(item.rule_id.startswith("contract-undeclared-") or item.rule_id.startswith("contract-contradicted-") for item in evidence) and score >= 14:
        return "suspicious", min(0.86, 0.50 + score / 160)
    if any(item.rule_id == "hidden-files" for item in evidence):
        return "suspicious", 0.58
    if any(item.rule_id in {"excessive-permissions"} for item in evidence) and score >= 14:
        return "suspicious", min(0.84, 0.48 + score / 170)
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


def _category_priority(category: str, evidence: list[Evidence]) -> float:
    rule_ids = {item.rule_id for item in evidence if item.category == category}
    if category == "AST-01":
        return 18.0
    if category == "AST-02" and rule_ids & {"data-exfiltration", "credential-store-access", "secret-file-access", "prompt-injection-forced-exfiltration"}:
        return 12.0
    if category == "AST-05" and "remote-code-pipe" in rule_ids:
        return 11.0
    if category == "AST-08" and "destructive-filesystem" in rule_ids:
        return 10.0
    if category == "AST-06" and "persistence-hook" in rule_ids:
        return 8.0
    if category == "AST-09" and "obfuscated-payload" in rule_ids:
        return 7.0
    if category == "AST-10":
        return -10.0
    if category == "AST-07":
        return -7.0
    return 0.0
