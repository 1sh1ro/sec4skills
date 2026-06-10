from __future__ import annotations


# The competition asks for OWASP AST-style explainability. The public AST10
# taxonomy is still young, so each category is kept descriptive and stable.
CATEGORIES: dict[str, str] = {
    "AST-01": "Malicious Skills",
    "AST-02": "Supply Chain Compromise",
    "AST-03": "Over-Privileged Skills",
    "AST-04": "Insecure Metadata",
    "AST-05": "Unsafe Deserialization",
    "AST-06": "Weak Isolation",
    "AST-07": "Update Drift",
    "AST-08": "Poor Scanning",
    "AST-09": "No Governance",
    "AST-10": "Cross-Platform Reuse",
}


SEVERITY_SCORES: dict[str, int] = {
    "info": 1,
    "low": 3,
    "medium": 7,
    "high": 14,
    "critical": 24,
}


def category_name(category: str) -> str:
    return CATEGORIES.get(category, "Unmapped skill risk")
