from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .schema import Evidence


LABELS = ("benign", "suspicious", "malicious")
DEFAULT_POLICY_PATH = Path(__file__).with_name("rl_policy.json")


@dataclass(frozen=True)
class TrainingExample:
    label: str
    expected_category: str
    evidence: list[Evidence]
    score: int = 0
    source: str = "curated"


@dataclass(frozen=True)
class PolicyPrediction:
    label: str
    probabilities: dict[str, float]
    confidence: float
    contributors: list[dict[str, Any]]


def load_policy(path: Path | None = None) -> dict[str, Any] | None:
    policy_path = path or DEFAULT_POLICY_PATH
    if not policy_path.exists():
        return None
    try:
        return json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def apply_policy(result: dict[str, Any], policy: dict[str, Any] | None) -> dict[str, Any]:
    if not policy:
        result["rl_policy"] = {"enabled": False, "reason": "policy not found"}
        return result

    evidence = [evidence_from_dict(item) for item in result.get("evidence", [])]
    features = extract_features(evidence, int(result.get("risk_score", 0)))
    prediction = predict(features, policy)
    blended = blend_decision(result["label"], result["confidence"], prediction)

    result["label"] = blended["label"]
    result["malicious"] = result["label"] == "malicious"
    result["confidence"] = blended["confidence"]
    result["rl_policy"] = {
        "enabled": True,
        "prediction": prediction.label,
        "probabilities": prediction.probabilities,
        "top_feature_contributors": prediction.contributors,
        "blended_from": blended["source"],
        "reward_profile": policy.get("reward_profile", {}),
        "training_examples": policy.get("training_examples"),
        "corpus_examples": policy.get("corpus_examples"),
        "validation_examples": policy.get("validation_examples"),
        "validation_metrics": policy.get("validation_metrics"),
        "cross_validation": policy.get("cross_validation"),
    }
    return result


def train_policy(
    examples: list[TrainingExample],
    epochs: int = 30,
    learning_rate: float = 0.04,
) -> dict[str, Any]:
    weights: dict[str, dict[str, float]] = {label: {} for label in LABELS}
    labels = {example.label for example in examples}
    if not labels <= set(LABELS):
        raise ValueError(f"Unsupported labels: {sorted(labels - set(LABELS))}")

    for _ in range(epochs):
        for example in examples:
            features = extract_features(example.evidence, example.score)
            prediction = predict_label(features, weights)
            if prediction == example.label:
                continue

            penalty = _mistake_penalty(example.label, prediction)
            for name, value in features.items():
                weights[example.label][name] = weights[example.label].get(name, 0.0) + learning_rate * penalty * value
                weights[prediction][name] = weights[prediction].get(name, 0.0) - learning_rate * penalty * value

    return {
        "version": 1,
        "labels": list(LABELS),
        "weights": _rounded_weights(weights),
        "reward_profile": {
            "objective": "F2-oriented contextual bandit evidence scorer",
            "false_negative_penalty": 5.0,
            "false_positive_penalty": 2.0,
            "suspicious_margin_penalty": 1.3,
            "category_match_bonus": 0.5,
        },
        "training_examples": len(examples),
    }


def split_examples(
    examples: list[TrainingExample],
    validation_ratio: float = 0.25,
    seed: int = 17,
) -> tuple[list[TrainingExample], list[TrainingExample]]:
    """Create a deterministic stratified holdout without leaking samples across splits."""
    if not 0.0 <= validation_ratio < 1.0:
        raise ValueError("validation_ratio must be in [0.0, 1.0)")
    if not examples or validation_ratio == 0.0:
        return list(examples), []

    by_label: dict[str, list[tuple[int, TrainingExample]]] = {label: [] for label in LABELS}
    for index, example in enumerate(examples):
        by_label.setdefault(example.label, []).append((index, example))

    validation_indices: set[int] = set()
    for label in LABELS:
        indexed = by_label.get(label, [])
        if len(indexed) < 2:
            continue
        holdout_count = max(1, math.ceil(len(indexed) * validation_ratio))
        holdout_count = min(holdout_count, len(indexed) - 1)
        ordered = sorted(indexed, key=lambda item: _split_key(item[1], item[0], seed))
        validation_indices.update(index for index, _ in ordered[:holdout_count])

    train = [example for index, example in enumerate(examples) if index not in validation_indices]
    validation = [example for index, example in enumerate(examples) if index in validation_indices]
    return train, validation


def cross_validate_policy(
    examples: list[TrainingExample],
    folds: int = 5,
    epochs: int = 30,
    learning_rate: float = 0.04,
    seed: int = 17,
) -> dict[str, Any]:
    if folds < 2 or len(examples) < 2:
        return {"enabled": False, "reason": "need at least two folds and two examples"}

    assignments = _fold_assignments(examples, folds, seed)
    fold_results: list[dict[str, Any]] = []
    for fold in range(folds):
        validation = [example for index, example in enumerate(examples) if assignments.get(index) == fold]
        train = [example for index, example in enumerate(examples) if assignments.get(index) != fold]
        if not validation or not train:
            continue
        policy = train_policy(train, epochs=epochs, learning_rate=learning_rate)
        fold_results.append(
            {
                "fold": fold + 1,
                "train_examples": len(train),
                "validation_examples": len(validation),
                "metrics": _without_records(evaluate_policy(validation, policy)),
            }
        )

    if not fold_results:
        return {"enabled": False, "reason": "no non-empty folds"}
    return {
        "enabled": True,
        "folds": len(fold_results),
        "aggregate": _aggregate_fold_metrics(fold_results),
        "fold_results": fold_results,
    }


def evaluate_policy(examples: list[TrainingExample], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    if policy is None:
        policy = train_policy(examples)

    confusion: dict[str, Counter[str]] = {label: Counter() for label in LABELS}
    category_total = 0
    category_correct = 0
    records: list[dict[str, Any]] = []

    for example in examples:
        features = extract_features(example.evidence, example.score)
        prediction = predict(features, policy)
        predicted_category = _primary_category(example.evidence)
        confusion[example.label][prediction.label] += 1
        if example.expected_category:
            category_total += 1
            if predicted_category == example.expected_category:
                category_correct += 1
        records.append(
            {
                "source": example.source,
                "label": example.label,
                "prediction": prediction.label,
                "expected_category": example.expected_category,
                "predicted_category": predicted_category,
            }
        )

    tp = confusion["malicious"]["malicious"]
    fn = sum(confusion["malicious"][label] for label in LABELS if label != "malicious")
    fp = sum(confusion[label]["malicious"] for label in LABELS if label != "malicious")
    tn = sum(
        confusion[expected][predicted]
        for expected in LABELS
        for predicted in LABELS
        if expected != "malicious" and predicted != "malicious"
    )
    total = len(examples)
    accuracy = sum(confusion[label][label] for label in LABELS) / total if total else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    beta2 = 4.0
    f2 = (1 + beta2) * precision * recall / (beta2 * precision + recall) if precision + recall else 0.0

    return {
        "total": total,
        "accuracy": round(accuracy, 4),
        "precision_malicious": round(precision, 4),
        "recall_malicious": round(recall, 4),
        "f2_malicious": round(f2, 4),
        "false_negatives": int(fn),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "category_accuracy": round(category_correct / category_total, 4) if category_total else 0.0,
        "confusion": {label: dict(confusion[label]) for label in LABELS},
        "records": records,
    }


def extract_features(evidence: list[Evidence], score: int) -> dict[str, float]:
    features: dict[str, float] = {
        "bias": 1.0,
        "risk_score": score / 100.0,
        "evidence_count": min(len(evidence), 24) / 24.0,
    }
    severity_counts = Counter(item.severity for item in evidence)
    category_counts = Counter(item.category for item in evidence)
    rule_counts = Counter(item.rule_id for item in evidence)

    for severity in ("low", "medium", "high", "critical"):
        features[f"sev:{severity}"] = min(severity_counts[severity], 8) / 8.0
    for category in sorted(category_counts):
        features[f"cat:{category}"] = min(category_counts[category], 8) / 8.0
    for rule_id in sorted(rule_counts):
        features[f"rule:{rule_id}"] = min(rule_counts[rule_id], 4) / 4.0

    features["combo:secret_egress"] = _has_any(evidence, {"secret-file-access", "data-exfiltration", "contract-secret-egress-combo"})
    features["combo:canary"] = _has_prefix(evidence, "canary-")
    features["combo:contract_mismatch"] = _has_prefix(evidence, "contract-undeclared-")
    features["combo:benign_low_evidence"] = 1.0 if score < 18 and len(evidence) <= 2 else 0.0
    return features


def predict(features: dict[str, float], policy: dict[str, Any]) -> PolicyPrediction:
    weights = policy.get("weights", {})
    scores = {
        label: sum(float(weights.get(label, {}).get(name, 0.0)) * value for name, value in features.items())
        for label in LABELS
    }
    probabilities = _softmax(scores)
    label = max(probabilities, key=probabilities.get)
    contributors = _contributors(label, features, weights.get(label, {}))
    return PolicyPrediction(label, probabilities, probabilities[label], contributors)


def predict_label(features: dict[str, float], weights: dict[str, dict[str, float]]) -> str:
    scores = {
        label: sum(weights.get(label, {}).get(name, 0.0) * value for name, value in features.items())
        for label in LABELS
    }
    return max(scores, key=scores.get)


def blend_decision(static_label: str, static_confidence: float, prediction: PolicyPrediction) -> dict[str, Any]:
    if static_label == prediction.label:
        return {
            "label": static_label,
            "confidence": round(min(0.99, max(static_confidence, prediction.confidence)), 4),
            "source": "static+rl-agree",
        }
    if static_label == "malicious" and prediction.label == "benign":
        return {"label": "suspicious", "confidence": 0.72, "source": "rl-downgraded-static-malicious"}
    if static_label == "benign" and prediction.label == "malicious":
        return {"label": "suspicious", "confidence": 0.70, "source": "rl-raised-static-benign"}
    if prediction.confidence >= 0.72:
        return {"label": prediction.label, "confidence": round(prediction.confidence, 4), "source": "rl-high-confidence"}
    return {"label": static_label, "confidence": round(static_confidence, 4), "source": "static-retained"}


def write_policy(path: Path, policy: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evidence_from_dict(item: dict[str, Any]) -> Evidence:
    return Evidence(
        file=str(item.get("file", ".")),
        line=int(item.get("line", 1)),
        message=str(item.get("message", "")),
        snippet=str(item.get("snippet", "")),
        category=str(item.get("category", "AST-UNKNOWN")),
        severity=str(item.get("severity", "medium")),
        rule_id=str(item.get("rule_id", "generic")),
        weight=float(item.get("weight", 1.0)),
    )


def _has_any(evidence: list[Evidence], rule_ids: set[str]) -> float:
    return 1.0 if any(item.rule_id in rule_ids for item in evidence) else 0.0


def _has_prefix(evidence: list[Evidence], prefix: str) -> float:
    return 1.0 if any(item.rule_id.startswith(prefix) for item in evidence) else 0.0


def _primary_category(evidence: list[Evidence]) -> str:
    counts = Counter(item.category for item in evidence)
    if not counts:
        return "BENIGN"
    return counts.most_common(1)[0][0]


def _mistake_penalty(expected: str, predicted: str) -> float:
    if expected == "malicious" and predicted != "malicious":
        return 5.0
    if expected != "malicious" and predicted == "malicious":
        return 2.0
    return 1.3


def _split_key(example: TrainingExample, index: int, seed: int) -> str:
    rule_ids = ",".join(sorted(item.rule_id for item in example.evidence))
    payload = f"{seed}|{index}|{example.label}|{example.expected_category}|{example.source}|{example.score}|{rule_ids}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _fold_assignments(examples: list[TrainingExample], folds: int, seed: int) -> dict[int, int]:
    by_label: dict[str, list[tuple[int, TrainingExample]]] = {label: [] for label in LABELS}
    for index, example in enumerate(examples):
        by_label.setdefault(example.label, []).append((index, example))

    assignments: dict[int, int] = {}
    for label in LABELS:
        ordered = sorted(by_label.get(label, []), key=lambda item: _split_key(item[1], item[0], seed))
        for offset, (index, _) in enumerate(ordered):
            assignments[index] = offset % folds
    return assignments


def _aggregate_fold_metrics(fold_results: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = [
        "accuracy",
        "precision_malicious",
        "recall_malicious",
        "f2_malicious",
        "false_negatives",
        "false_positives",
        "category_accuracy",
    ]
    aggregate: dict[str, Any] = {}
    for metric in metrics:
        values = [float(fold["metrics"].get(metric, 0.0)) for fold in fold_results]
        if not values:
            continue
        aggregate[f"mean_{metric}"] = round(sum(values) / len(values), 4)
        aggregate[f"min_{metric}"] = round(min(values), 4)
        aggregate[f"max_{metric}"] = round(max(values), 4)
    return aggregate


def _without_records(metrics: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metrics.items() if key != "records"}


def _softmax(scores: dict[str, float]) -> dict[str, float]:
    max_score = max(scores.values()) if scores else 0.0
    exps = {label: math.exp(score - max_score) for label, score in scores.items()}
    total = sum(exps.values()) or 1.0
    return {label: round(value / total, 4) for label, value in exps.items()}


def _contributors(label: str, features: dict[str, float], weights: dict[str, float]) -> list[dict[str, Any]]:
    scored = [
        {"feature": name, "value": round(value, 4), "weight": round(weights.get(name, 0.0), 4), "impact": round(value * weights.get(name, 0.0), 4)}
        for name, value in features.items()
        if abs(value * weights.get(name, 0.0)) > 0.0001
    ]
    scored.sort(key=lambda item: abs(float(item["impact"])), reverse=True)
    return scored[:8]


def _rounded_weights(weights: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    return {
        label: {
            name: round(value, 6)
            for name, value in sorted(label_weights.items())
            if abs(value) > 0.000001
        }
        for label, label_weights in weights.items()
    }
