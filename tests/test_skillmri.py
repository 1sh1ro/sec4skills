from __future__ import annotations

from pathlib import Path

from skillmri.cli import contest_category, run_contest_batch, scan_path_manifest, summarize_path_rows
from skillmri.rl_policy import cross_validate_policy, split_examples, train_policy
from skillmri.scanner import scan
from skillmri.schema import ScanOptions
from skillmri.training_corpus import build_dataset, load_training_examples, scan_manifest_samples, summarize_rows, write_jsonl


ROOT = Path(__file__).resolve().parents[1]


def test_malicious_example_is_detected() -> None:
    result = scan(ROOT / "examples" / "malicious_skill", ScanOptions(sandbox="simulate"))

    assert result["label"] == "malicious"
    assert result["risk_score"] >= 45
    assert result["primary_category"] in {"AST-01", "AST-02", "AST-03", "AST-05"}
    assert any(item["rule_id"] == "canary-simulated-secret-egress" for item in result["evidence"])


def test_benign_example_remains_low_risk() -> None:
    result = scan(ROOT / "examples" / "benign_skill", ScanOptions(sandbox="simulate"))

    assert result["label"] in {"benign", "suspicious"}
    assert result["risk_score"] < 18
    assert not result["malicious"]


def test_curated_dataset_has_high_malicious_recall(tmp_path: Path) -> None:
    build_dataset(tmp_path)
    rows = scan_manifest_samples(tmp_path / "manifest.json", use_policy=False)
    summary = summarize_rows(rows)

    assert summary["total"] >= 70
    assert summary["recall_malicious"] >= 0.96
    assert summary["f2_malicious"] >= 0.95


def test_default_policy_metadata_is_reported() -> None:
    result = scan(ROOT / "examples" / "malicious_skill", ScanOptions(sandbox="simulate"))

    assert result["rl_policy"]["enabled"] is True
    assert result["rl_policy"]["prediction"] in {"benign", "suspicious", "malicious"}
    assert result["rl_policy"]["validation_examples"] is not None


def test_rl_training_uses_stratified_holdout(tmp_path: Path) -> None:
    build_dataset(tmp_path / "corpus")
    rows = scan_manifest_samples(tmp_path / "corpus" / "manifest.json", use_policy=False)
    jsonl = tmp_path / "training.jsonl"
    write_jsonl(rows, jsonl)
    examples = load_training_examples([jsonl])

    train, validation = split_examples(examples, validation_ratio=0.25, seed=17)
    policy = train_policy(train, epochs=5)
    cross_validation = cross_validate_policy(examples, folds=5, epochs=5)

    assert len(train) + len(validation) == len(examples)
    assert {example.label for example in validation} == {"benign", "suspicious", "malicious"}
    assert policy["training_examples"] == len(train)
    assert cross_validation["enabled"] is True
    assert cross_validation["aggregate"]["mean_f2_malicious"] >= 0.0


def test_eval_paths_manifest_normalizes_external_labels(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        (
            "["
            f'{{"name":"benign","path":"{ROOT / "examples" / "benign_skill"}","classification":"safe"}},'
            f'{{"name":"malicious","path":"{ROOT / "examples" / "malicious_skill"}","classification":"malicious"}}'
            "]"
        ),
        encoding="utf-8",
    )

    rows = scan_path_manifest(manifest)
    summary = summarize_path_rows(rows)

    assert {row["label"] for row in rows} == {"benign", "malicious"}
    assert summary["total"] == 2
    assert summary["recall_malicious"] == 1.0


def test_contest_batch_outputs_required_rows(tmp_path: Path) -> None:
    input_dir = tmp_path / "skills"
    input_dir.mkdir()
    for name, source in {
        "benign_001": ROOT / "examples" / "benign_skill",
        "malicious_001": ROOT / "examples" / "malicious_skill",
    }.items():
        target = input_dir / name
        target.mkdir()
        for path in source.iterdir():
            (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    rows = run_contest_batch(input_dir, ScanOptions(sandbox="simulate"))

    assert [row["skill_id"] for row in rows] == ["benign_001", "malicious_001"]
    assert {row["verdict"] for row in rows} >= {"benign", "malicious"}
    assert all(row["category"].startswith("AST") for row in rows)
    assert all("evidence" in row for row in rows)


def test_contest_category_uses_ast01_format() -> None:
    assert contest_category("AST-01") == "AST01"
    assert contest_category("AST-10") == "AST10"
    assert contest_category("BENIGN") == "AST10"
