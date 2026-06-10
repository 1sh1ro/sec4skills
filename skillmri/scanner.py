from __future__ import annotations

from pathlib import Path
from typing import Any

from .collector import collect_files
from .contract import audit_contract
from .features import declaration_text, infer_actual_capabilities, infer_declared_capabilities, infer_negative_declarations
from .online_llm import online_llm_evidence
from .rl_policy import apply_policy, load_policy
from .sandbox import run_canary_sandbox
from .schema import ScanContext, ScanOptions
from .scorer import build_result
from .semantic_model import load_semantic_model, semantic_evidence
from .static_rules import run_static_rules


def scan(target: Path, options: ScanOptions) -> dict[str, Any]:
    target = target.resolve()
    files = collect_files(target, options)
    declared_text, manifest_text = declaration_text(files)
    ctx = ScanContext(
        target=target,
        files=files,
        declared_text=declared_text,
        manifest_text=manifest_text,
        declared_capabilities=infer_declared_capabilities(declared_text),
        negative_declarations=infer_negative_declarations(declared_text),
        actual_capabilities=infer_actual_capabilities(files),
        stats={
            "files_scanned": len(files),
            "binary_files": sum(1 for record in files if record.is_binary),
        },
    )

    ctx.evidence.extend(run_static_rules(files))
    ctx.evidence.extend(audit_contract(ctx))
    ctx.evidence.extend(run_canary_sandbox(ctx, options.sandbox))
    if options.use_semantic_model:
        semantic_hits, semantic_stats = semantic_evidence(files, load_semantic_model(options.semantic_model_path))
        ctx.evidence.extend(semantic_hits)
        ctx.stats["semantic_model"] = semantic_stats
    else:
        ctx.stats["semantic_model"] = {"enabled": False, "reason": "disabled"}
    online_hits, online_stats = online_llm_evidence(files, ctx.evidence, options)
    ctx.evidence.extend(online_hits)
    ctx.stats["online_classifier"] = online_stats
    ctx.stats["declared_capabilities"] = sorted(ctx.declared_capabilities)
    ctx.stats["negative_declarations"] = sorted(ctx.negative_declarations)
    ctx.stats["actual_capabilities"] = sorted(ctx.actual_capabilities)
    result = build_result(str(target), ctx.evidence, ctx.stats)
    if options.use_policy:
        return apply_policy(result, load_policy(options.policy_path))

    result["rl_policy"] = {"enabled": False, "reason": "disabled"}
    return result
