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
        primary_category = max(category_counts, key=lambda category: weighted_category_score(grouped[category]))

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
    for item in evidence:
        key = (item.rule_id, item.file, item.line, item.category)
        if key in seen:
            continue
        seen.add(key)
        raw += SEVERITY_SCORES.get(item.severity, 5) * item.weight
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
    return min(100, max(0, int(round(raw))))


def weighted_category_score(evidence: list[Evidence]) -> float:
    return sum(SEVERITY_SCORES.get(item.severity, 5) * item.weight for item in evidence)


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
