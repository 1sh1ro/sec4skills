from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .rl_policy import DEFAULT_POLICY_PATH, cross_validate_policy, evaluate_policy, split_examples, train_policy, write_policy
from .scanner import scan
from .schema import ScanOptions
from .semantic_model import DEFAULT_SEMANTIC_MODEL_PATH, train_semantic_command
from .training_corpus import build_dataset, load_training_examples, scan_manifest_samples, summarize_rows, write_jsonl


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"scan", "contest", "build-dataset", "train-rl", "train-semantic", "eval-dataset", "eval-paths"}:
        command = argv.pop(0)
    else:
        command = "scan"

    if command == "contest":
        return contest_command(argv)
    if command == "build-dataset":
        return build_dataset_command(argv)
    if command == "train-rl":
        return train_rl_command(argv)
    if command == "train-semantic":
        return train_semantic_command(argv)
    if command == "eval-dataset":
        return eval_dataset_command(argv)
    if command == "eval-paths":
        return eval_paths_command(argv)

    parser = build_scan_parser(prog="skillmri" if command == "scan" else "skillmri scan")
    args = parser.parse_args(argv)
    options = ScanOptions(
        max_file_bytes=args.max_file_bytes,
        max_total_files=args.max_total_files,
        sandbox=args.sandbox,
        output=args.output,
        fail_on_malicious=args.fail_on_malicious,
        use_policy=not args.no_rl_policy,
        policy_path=args.rl_model,
        use_semantic_model=not args.no_semantic_model,
        semantic_model_path=args.semantic_model,
    )
    result = scan(Path(args.target), options)
    emit_result(result, args.output)
    if args.fail_on_malicious and result["malicious"]:
        return 2
    return 0


def build_scan_parser(prog: str = "skillmri") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Offline scanner for malicious or misleading Agent Skills.",
    )
    parser.add_argument("target", help="Skill directory or file to scan")
    parser.add_argument("--version", action="version", version=f"skillmri {__version__}")
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    parser.add_argument("--sandbox", choices=("off", "simulate", "run"), default="simulate")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-total-files", type=int, default=2500)
    parser.add_argument("--fail-on-malicious", action="store_true")
    parser.add_argument("--rl-model", type=Path, default=None, help="Optional RL evidence scorer policy JSON")
    parser.add_argument("--no-rl-policy", action="store_true", help="Disable the default packaged RL evidence scorer")
    parser.add_argument("--semantic-model", type=Path, default=None, help="Optional lightweight semantic classifier JSON")
    parser.add_argument("--no-semantic-model", action="store_true", help="Disable the packaged semantic classifier")
    return parser


def contest_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skillmri contest",
        description="Run the Skill CTF blue-team Docker interface: /data/skills/* -> /output/results.jsonl.",
    )
    parser.add_argument("--input-dir", type=Path, default=None)
    parser.add_argument("--output-file", type=Path, default=None)
    parser.add_argument("--sandbox", choices=("off", "simulate", "run"), default="simulate")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-total-files", type=int, default=2500)
    parser.add_argument("--no-rl-policy", action="store_true", help="Disable the default packaged RL evidence scorer")
    parser.add_argument("--semantic-model", type=Path, default=None, help="Optional lightweight semantic classifier JSON")
    parser.add_argument("--no-semantic-model", action="store_true", help="Disable the packaged semantic classifier")
    args = parser.parse_args(argv)

    options = ScanOptions(
        max_file_bytes=args.max_file_bytes,
        max_total_files=args.max_total_files,
        sandbox=args.sandbox,
        output="json",
        use_policy=not args.no_rl_policy,
        use_semantic_model=not args.no_semantic_model,
        semantic_model_path=args.semantic_model,
    )
    input_dir = args.input_dir or _default_contest_input_dir()
    rows = run_contest_batch(input_dir, options)
    output_files = [args.output_file] if args.output_file else _default_contest_output_files()
    for index, output_file in enumerate(_unique_paths(output_files)):
        try:
            _write_contest_rows(output_file, rows)
        except OSError:
            if index == 0:
                raise
    return 0


def run_contest_batch(input_dir: Path, options: ScanOptions) -> list[dict[str, Any]]:
    if not input_dir.exists():
        return [
            {
                "skill_id": "__input_missing__",
                "verdict": "suspicious",
                "confidence": 0.5,
                "category": "AST10",
                "evidence": f"Input directory not found: {input_dir}",
            }
        ]

    targets = discover_contest_targets(input_dir)
    input_root = input_dir.resolve() if input_dir.is_dir() else input_dir.parent.resolve()

    rows: list[dict[str, Any]] = []
    for target in targets:
        skill_id = contest_skill_id(target, input_root)
        try:
            result = scan(target, options)
            rows.append(contest_row(skill_id, result))
        except Exception as exc:  # Keep the batch alive for robustness scoring.
            rows.append(
                {
                    "skill_id": skill_id,
                    "verdict": "suspicious",
                    "confidence": 0.5,
                    "category": "AST10",
                    "evidence": f"Scanner error: {type(exc).__name__}: {exc}",
                }
            )
    return rows


def discover_contest_targets(input_dir: Path) -> list[Path]:
    """Find skill package roots without assuming one exact evaluator layout."""
    if input_dir.is_file():
        return [input_dir]

    input_dir = input_dir.resolve()
    if _looks_like_skill_root(input_dir):
        return [input_dir]

    children = sorted(path for path in input_dir.iterdir() if path.is_dir())
    direct_roots = [path for path in children if _looks_like_skill_root(path)]
    if direct_roots:
        return direct_roots

    nested_roots: list[Path] = []
    for path in sorted(input_dir.rglob("*")):
        if not path.is_dir() or not _looks_like_skill_root(path):
            continue
        if any(_is_relative_to(path, root) for root in nested_roots):
            continue
        nested_roots.append(path)
    if nested_roots:
        return nested_roots

    if not children and any(path.is_file() for path in input_dir.iterdir()):
        return [input_dir]

    return children


def contest_skill_id(target: Path, input_root: Path | None = None) -> str:
    if target.is_file():
        return target.stem

    if input_root is not None and _is_direct_child(target, input_root):
        return target.name

    for metadata_name in ("manifest.json", "skill.json"):
        metadata_path = target / metadata_name
        value = _metadata_skill_id(metadata_path)
        if value:
            return value
    return target.name


def _looks_like_skill_root(path: Path) -> bool:
    if path.is_file():
        return True
    if not path.is_dir():
        return False
    root_markers = {
        "manifest.json",
        "skill.json",
        "SKILL.md",
        "skill.md",
        "README.md",
        "readme.md",
        "AGENTS.md",
        "agents.md",
    }
    return any((path / marker).is_file() for marker in root_markers)


def _metadata_skill_id(metadata_path: Path) -> str:
    if not metadata_path.is_file():
        return ""
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""

    if not isinstance(payload, dict):
        return ""
    for key in (
        "skill_id",
        "skillId",
        "id",
        "name",
        "slug",
        "identifier",
        "package",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_direct_child(path: Path, parent: Path) -> bool:
    try:
        return path.resolve().parent == parent.resolve()
    except OSError:
        return False


def contest_row(skill_id: str, result: dict[str, Any]) -> dict[str, Any]:
    evidence_items = result.get("evidence", [])
    evidence = "; ".join(
        f"{item.get('rule_id', 'rule')} {item.get('file', '.')}:{item.get('line', 1)} {item.get('message', '')}"
        for item in evidence_items[:5]
    )
    if not evidence:
        evidence = "No high-risk evidence found."
    category = contest_category(str(result.get("primary_category", "AST-10")))
    verdict = result.get("label", "suspicious")
    return {
        "skill_id": skill_id,
        "verdict": verdict,
        "confidence": round(float(result.get("confidence", 0.5)), 4),
        "category": category,
        "evidence": evidence[:2000],
        "engine_category": "benign" if verdict == "benign" else category.lower(),
        "evidence_text": evidence[:2000],
    }


def contest_category(category: str) -> str:
    normalized = category.strip().upper().replace("-", "")
    if normalized == "BENIGN":
        return "AST10"
    if normalized.startswith("AST") and normalized[3:].isdigit():
        number = int(normalized[3:])
        if 1 <= number <= 10:
            return f"AST{number:02d}"
    return "AST10"


def _default_contest_output_files() -> list[Path]:
    import os

    output_dir = os.environ.get("SKILLSEC_OUTPUT_DIR")
    if output_dir:
        return [Path(output_dir) / "results.jsonl", Path("/output/results.jsonl")]
    return [Path("/output/results.jsonl")]


def _default_contest_input_dir() -> Path:
    import os

    return Path(os.environ.get("SKILLSEC_INPUT_DIR", "/data/skills"))


def _write_contest_rows(output_file: Path, rows: list[dict[str, Any]]) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _unique_paths(paths: list[Path | None]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        if path is None:
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def build_dataset_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skillmri build-dataset",
        description="Build curated Agent Skill samples and scan them into a JSONL training corpus.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("examples/curated_corpus"))
    parser.add_argument("--jsonl", type=Path, default=Path("examples/rl_curated_training.jsonl"))
    parser.add_argument("--sandbox", choices=("off", "simulate", "run"), default="simulate")
    parser.add_argument("--keep", action="store_true", help="Keep existing output directory contents")
    parser.add_argument("--output", choices=("json", "summary"), default="summary")
    args = parser.parse_args(argv)

    manifest = build_dataset(args.output_dir, clean=not args.keep)
    rows = scan_manifest_samples(args.output_dir / "manifest.json", sandbox=args.sandbox, use_policy=False)
    write_jsonl(rows, args.jsonl)
    summary = summarize_rows(rows)
    payload = {
        "samples": len(manifest),
        "manifest": str(args.output_dir / "manifest.json"),
        "jsonl": str(args.jsonl),
        "label_counts": _count_by(manifest, "label"),
        "source_counts": _count_by(manifest, "source"),
        "static_eval": summary,
    }
    emit_payload(payload, args.output)
    return 0


def train_rl_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skillmri train-rl",
        description="Train the lightweight F2-oriented RL evidence scorer from scanned JSONL samples.",
    )
    parser.add_argument("jsonl", nargs="+", type=Path)
    parser.add_argument("--output-model", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--epochs", type=int, default=35)
    parser.add_argument("--learning-rate", type=float, default=0.04)
    parser.add_argument("--validation-ratio", type=float, default=0.25)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--output", choices=("json", "summary"), default="summary")
    args = parser.parse_args(argv)

    examples = load_training_examples(args.jsonl)
    train_examples, validation_examples = split_examples(examples, validation_ratio=args.validation_ratio, seed=args.seed)
    policy = train_policy(train_examples, epochs=args.epochs, learning_rate=args.learning_rate)
    policy["corpus_examples"] = len(examples)
    policy["validation_examples"] = len(validation_examples)
    policy["training_config"] = {
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "validation_ratio": args.validation_ratio,
        "cv_folds": args.cv_folds,
        "seed": args.seed,
    }
    train_metrics = evaluate_policy(train_examples, policy)
    validation_metrics = evaluate_policy(validation_examples, policy) if validation_examples else {}
    if validation_metrics:
        policy["validation_metrics"] = _without_records(validation_metrics)
    cross_validation = cross_validate_policy(
        examples,
        folds=args.cv_folds,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        seed=args.seed,
    )
    if cross_validation.get("enabled"):
        policy["cross_validation"] = {
            "folds": cross_validation["folds"],
            "aggregate": cross_validation["aggregate"],
        }
    write_policy(args.output_model, policy)
    payload = {
        "model": str(args.output_model),
        "corpus_examples": len(examples),
        "training_examples": len(train_examples),
        "validation_examples": len(validation_examples),
        "train_metrics": _without_records(train_metrics),
        "validation_metrics": _without_records(validation_metrics) if validation_metrics else None,
        "cross_validation": cross_validation,
        "reward_profile": policy.get("reward_profile", {}),
    }
    emit_payload(payload, args.output)
    return 0


def eval_dataset_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skillmri eval-dataset",
        description="Evaluate scanner verdicts against a generated dataset manifest.",
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--sandbox", choices=("off", "simulate", "run"), default="simulate")
    parser.add_argument("--no-rl-policy", action="store_true", help="Evaluate static scanner only")
    parser.add_argument("--output", choices=("json", "summary"), default="summary")
    args = parser.parse_args(argv)

    rows = scan_manifest_samples(args.manifest, sandbox=args.sandbox, use_policy=not args.no_rl_policy)
    payload = summarize_rows(rows)
    payload["samples"] = len(rows)
    payload["rl_policy"] = "disabled" if args.no_rl_policy else "enabled"
    emit_payload(payload, args.output)
    return 0


def eval_paths_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skillmri eval-paths",
        description="Evaluate scanner verdicts against a JSON manifest of arbitrary local skill paths.",
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--sandbox", choices=("off", "simulate", "run"), default="simulate")
    parser.add_argument("--no-rl-policy", action="store_true", help="Evaluate static scanner only")
    parser.add_argument("--output", choices=("json", "summary"), default="summary")
    args = parser.parse_args(argv)

    rows = scan_path_manifest(args.manifest, sandbox=args.sandbox, use_policy=not args.no_rl_policy)
    payload = summarize_path_rows(rows)
    payload["samples"] = len(rows)
    payload["rl_policy"] = "disabled" if args.no_rl_policy else "enabled"
    emit_payload(payload, args.output)
    return 0


def scan_path_manifest(manifest_path: Path, sandbox: str = "simulate", use_policy: bool = True) -> list[dict[str, Any]]:
    records = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("path manifest must be a JSON array")
    root = manifest_path.parent
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(records, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"path manifest row {index} must be an object")
        path_value = item.get("path") or item.get("target")
        if not path_value:
            raise ValueError(f"path manifest row {index} missing path/target")
        target = Path(str(path_value))
        if not target.is_absolute():
            target = root / target
        label = normalize_expected_label(str(item.get("label") or item.get("classification") or item.get("expected") or ""))
        result = scan(target, ScanOptions(sandbox=sandbox, use_policy=use_policy))
        rows.append(
            {
                **item,
                "name": str(item.get("name") or target.name),
                "path": str(target),
                "label": label,
                "prediction": result["label"],
                "malicious": result["malicious"],
                "risk_score": result["risk_score"],
                "confidence": result["confidence"],
                "primary_category": result["primary_category"],
                "evidence_count": len(result["evidence"]),
            }
        )
    return rows


def summarize_path_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = ("benign", "suspicious", "malicious")
    confusion = {label: {predicted: 0 for predicted in labels} for label in labels}
    skipped = 0
    misclassified: list[dict[str, Any]] = []
    for row in rows:
        label = str(row.get("label", ""))
        prediction = str(row.get("prediction", ""))
        if label not in confusion or prediction not in confusion[label]:
            skipped += 1
            continue
        confusion[label][prediction] += 1
        if label != prediction:
            misclassified.append(
                {
                    "name": row.get("name", ""),
                    "label": label,
                    "prediction": prediction,
                    "risk_score": row.get("risk_score"),
                    "primary_category": row.get("primary_category"),
                }
            )

    total = sum(sum(predicted.values()) for predicted in confusion.values())
    correct = sum(confusion[label][label] for label in labels)
    tp = confusion["malicious"]["malicious"]
    fn = sum(confusion["malicious"][label] for label in labels if label != "malicious")
    fp = sum(confusion[label]["malicious"] for label in labels if label != "malicious")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    beta2 = 4.0
    f2 = (1 + beta2) * precision * recall / (beta2 * precision + recall) if precision + recall else 0.0
    benign_total = sum(confusion["benign"].values())
    strict_fp = confusion["benign"]["malicious"]
    non_benign = strict_fp + confusion["benign"]["suspicious"]

    return {
        "total": total,
        "skipped": skipped,
        "accuracy": round(correct / total, 4) if total else 0.0,
        "precision_malicious": round(precision, 4),
        "recall_malicious": round(recall, 4),
        "f2_malicious": round(f2, 4),
        "false_negatives": int(fn),
        "false_positives": int(fp),
        "benign_strict_fp_rate": round(strict_fp / benign_total, 4) if benign_total else 0.0,
        "benign_non_benign_rate": round(non_benign / benign_total, 4) if benign_total else 0.0,
        "confusion": confusion,
        "misclassified": misclassified,
    }


def normalize_expected_label(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"safe", "clean", "benign"}:
        return "benign"
    if normalized in {"suspicious", "gray", "grey"}:
        return "suspicious"
    if normalized in {"malicious", "unsafe"}:
        return "malicious"
    return normalized


def emit_result(result: dict[str, Any], output: str) -> None:
    if output == "json":
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return

    print(f"Target: {result['target']}")
    print(f"Verdict: {result['label']} confidence={result['confidence']:.2f} score={result['risk_score']}")
    print(f"Primary category: {result['primary_category']} {result['primary_category_name']}")
    for item in result["evidence"][:20]:
        print(
            f"- [{item['severity']}] {item['category']} {item['rule_id']} "
            f"{item['file']}:{item['line']} {item['message']}"
        )
    rl_policy = result.get("rl_policy", {})
    if rl_policy.get("enabled"):
        print(f"RL policy: {rl_policy['prediction']} blended={rl_policy['blended_from']}")


def emit_payload(payload: dict[str, Any], output: str) -> None:
    if output == "json":
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return

    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            print(f"{key}: {json.dumps(value, ensure_ascii=False, sort_keys=True)}")
        else:
            print(f"{key}: {value}")


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key, ""))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _without_records(metrics: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metrics.items() if key != "records"}
