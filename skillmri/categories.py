from __future__ import annotations


# The competition asks for OWASP AST-style explainability. The public AST10
# taxonomy is still young, so each category is kept descriptive and stable.
CATEGORIES: dict[str, str] = {
    "AST-01": "Instruction and prompt injection",
    "AST-02": "Sensitive data access or exfiltration",
    "AST-03": "Dangerous tool, shell, or code execution",
    "AST-04": "Excessive permissions or privilege abuse",
    "AST-05": "Supply-chain or remote dependency risk",
    "AST-06": "Persistence, hidden hooks, or stealth behavior",
    "AST-07": "Unsafe network communication",
    "AST-08": "Destructive filesystem or environment modification",
    "AST-09": "Obfuscation or concealed payload",
    "AST-10": "Misleading capability declaration or behavior mismatch",
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
