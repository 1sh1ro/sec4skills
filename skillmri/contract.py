from __future__ import annotations

from .categories import category_name
from .schema import Evidence, ScanContext


CAPABILITY_TO_CATEGORY = {
    "network": "AST-06",
    "filesystem": "AST-03",
    "shell": "AST-06",
    "secrets": "AST-03",
    "delete": "AST-01",
    "persistence": "AST-01",
    "obfuscation": "AST-04",
}


def audit_contract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    undeclared = ctx.actual_capabilities - ctx.declared_capabilities

    # Obfuscation is not a legitimate declared capability for normal skills.
    if "obfuscation" in ctx.actual_capabilities:
        undeclared.add("obfuscation")

    for capability in sorted(undeclared):
        category = CAPABILITY_TO_CATEGORY.get(capability, "AST-10")
        severity = _severity_for(capability)
        evidence.append(
            Evidence(
                file=_best_declaration_file(ctx),
                line=1,
                message=(
                    f"Behavior mismatch: skill uses {capability!r} capability but does "
                    f"not clearly declare or justify it ({category_name(category)})."
                ),
                category=category,
                severity=severity,
                rule_id=f"contract-undeclared-{capability}",
                weight=1.2,
            )
        )

    contradictions = ctx.actual_capabilities & ctx.negative_declarations
    for capability in sorted(contradictions):
        category = CAPABILITY_TO_CATEGORY.get(capability, "AST-10")
        evidence.append(
            Evidence(
                file=_best_declaration_file(ctx),
                line=1,
                message=(
                    f"Behavior contradicts the declaration: skill says it avoids {capability!r} "
                    f"but observed code uses that capability."
                ),
                category=category,
                severity="high" if capability == "network" else _severity_for(capability),
                rule_id=f"contract-contradicted-{capability}",
                weight=1.3,
            )
        )

    dangerous_combo = {"network", "secrets"} <= ctx.actual_capabilities
    if dangerous_combo and "secrets" not in ctx.declared_capabilities:
        evidence.append(
            Evidence(
                file=_best_declaration_file(ctx),
                line=1,
                message="Capability graph combines secret access and network egress without an explicit user-facing reason.",
                category="AST-01",
                severity="critical",
                rule_id="contract-secret-egress-combo",
                weight=1.8,
            )
        )

    return evidence


def _best_declaration_file(ctx: ScanContext) -> str:
    for record in ctx.files:
        if record.path.name.lower() in {"skill.md", "agents.md", "readme.md", "plugin.json", "manifest.json"}:
            return record.relpath
    return "."


def _severity_for(capability: str) -> str:
    if capability in {"secrets", "delete"}:
        return "critical"
    if capability in {"shell", "persistence", "obfuscation"}:
        return "high"
    return "medium"
