from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .collector import collect_files
from .schema import Evidence, FileRecord, ScanOptions


LABELS = ("benign", "suspicious", "malicious")
DEFAULT_SEMANTIC_MODEL_PATH = Path(__file__).with_name("semantic_model.json")
TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_./:-]{1,48}|[0-9]{2,}")


@dataclass(frozen=True)
class SemanticExample:
    name: str
    label: str
    category: str
    files: list[FileRecord]
    source: str = "curated"


@dataclass(frozen=True)
class SemanticPrediction:
    label: str
    category: str
    probabilities: dict[str, float]
    category_probabilities: dict[str, float]
    confidence: float
    category_confidence: float
    margin: float
    contributors: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "category": self.category,
            "confidence": round(self.confidence, 4),
            "category_confidence": round(self.category_confidence, 4),
            "margin": round(self.margin, 4),
            "probabilities": self.probabilities,
            "category_probabilities": self.category_probabilities,
            "top_feature_contributors": self.contributors,
        }


def load_semantic_model(path: Path | None = None) -> dict[str, Any] | None:
    model_path = path or DEFAULT_SEMANTIC_MODEL_PATH
    if not model_path.exists():
        return None
    try:
        return json.loads(model_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def semantic_evidence(files: list[FileRecord], model: dict[str, Any] | None) -> tuple[list[Evidence], dict[str, Any]]:
    if not model:
        return [], {"enabled": False, "reason": "model not found"}
    prediction = predict_files(files, model)
    thresholds = model.get("thresholds", {})
    malicious_threshold = float(thresholds.get("malicious_confidence", 0.45))
    suspicious_threshold = float(thresholds.get("suspicious_confidence", 0.44))
    margin_threshold = float(thresholds.get("margin", 0.09))

    evidence: list[Evidence] = []
    category = _contest_internal_category(prediction.category, prediction.label)
    if prediction.label == "malicious" and prediction.confidence >= malicious_threshold and prediction.margin >= margin_threshold:
        evidence.append(
            Evidence(
                file="semantic://model",
                line=1,
                message=(
                    "Lightweight semantic classifier predicts malicious skill behavior "
                    f"(confidence={prediction.confidence:.3f}, category={category})."
                ),
                snippet=_top_contributor_snippet(prediction),
                category=category,
                severity="high",
                rule_id="semantic-ml-malicious",
                weight=0.8,
            )
        )
    elif prediction.label == "suspicious" and prediction.confidence >= suspicious_threshold and prediction.margin >= margin_threshold:
        evidence.append(
            Evidence(
                file="semantic://model",
                line=1,
                message=(
                    "Lightweight semantic classifier predicts suspicious skill behavior "
                    f"(confidence={prediction.confidence:.3f}, category={category})."
                ),
                snippet=_top_contributor_snippet(prediction),
                category=category,
                severity="medium",
                rule_id="semantic-ml-suspicious",
                weight=0.5,
            )
        )
    return evidence, {"enabled": True, **prediction.to_dict()}


def predict_files(files: list[FileRecord], model: dict[str, Any]) -> SemanticPrediction:
    features = vectorize_features(raw_features(files), model.get("vocabulary", []))
    label_scores = _scores(features, model.get("label_weights", {}), model.get("label_bias", {}))
    category_scores = _scores(features, model.get("category_weights", {}), model.get("category_bias", {}))
    probabilities = _softmax(label_scores, float(model.get("temperature", 1.8)))
    category_probabilities = _softmax(category_scores, float(model.get("temperature", 1.8)))
    label, confidence, margin = _top_with_margin(probabilities)
    category, category_confidence, _ = _top_with_margin(category_probabilities)
    contributors = _contributors(label, features, model.get("label_weights", {}).get(label, {}))
    return SemanticPrediction(
        label=label,
        category=category,
        probabilities=probabilities,
        category_probabilities=category_probabilities,
        confidence=confidence,
        category_confidence=category_confidence,
        margin=margin,
        contributors=contributors,
    )


def raw_features(files: list[FileRecord]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for record in files:
        suffix = record.path.suffix.lower()
        if suffix:
            counts[f"suffix:{suffix}"] += 1
        for part in Path(record.relpath).parts:
            for token in _tokens(part):
                counts[f"path:{token}"] += 1
        if record.is_binary:
            continue
        prefix = "doc" if record.path.suffix.lower() in {".md", ".mdx", ".rst", ".txt"} else "code"
        tokens = _tokens(record.text[:80_000])
        for token in tokens[:5000]:
            counts[f"{prefix}:{token}"] += 1
            counts[f"tok:{token}"] += 1
        for left, right in zip(tokens[:1800], tokens[1:1801]):
            counts[f"bi:{left}_{right}"] += 1
    return counts


def vectorize_features(counts: Counter[str], vocabulary: list[str]) -> dict[str, float]:
    vocab = set(vocabulary)
    return {
        feature: min(float(count), 4.0) / 4.0
        for feature, count in counts.items()
        if feature in vocab
    }


def train_semantic_model(
    examples: list[SemanticExample],
    *,
    epochs: int = 28,
    learning_rate: float = 0.08,
    max_features: int = 900,
    validation_ratio: float = 0.25,
    seed: int = 23,
) -> dict[str, Any]:
    train, validation = split_examples(examples, validation_ratio=validation_ratio, seed=seed)
    vocabulary = select_vocabulary(train, max_features=max_features)
    train_vectors = [(example, vectorize_features(raw_features(example.files), vocabulary)) for example in train]

    labels = list(LABELS)
    categories = sorted({example.category for example in examples if example.category and example.category != "BENIGN"})
    if "BENIGN" not in categories:
        categories.insert(0, "BENIGN")

    label_weights, label_bias = _train_linear(train_vectors, labels, lambda example: example.label, epochs, learning_rate, seed)
    category_weights, category_bias = _train_linear(
        train_vectors,
        categories,
        lambda example: example.category if example.category in categories else "BENIGN",
        epochs,
        learning_rate,
        seed + 31,
    )

    model = {
        "version": 1,
        "model_type": "hashed-ngram-linear-semantic-classifier",
        "labels": labels,
        "categories": categories,
        "vocabulary": vocabulary,
        "label_weights": _rounded_weights(label_weights),
        "label_bias": {key: round(value, 6) for key, value in sorted(label_bias.items())},
        "category_weights": _rounded_weights(category_weights),
        "category_bias": {key: round(value, 6) for key, value in sorted(category_bias.items())},
        "temperature": 1.8,
        "thresholds": {
            "malicious_confidence": 0.45,
            "suspicious_confidence": 0.44,
            "margin": 0.09,
        },
        "training_examples": len(train),
        "validation_examples": len(validation),
        "corpus_examples": len(examples),
        "validation_metrics": evaluate_semantic_model(validation, {
            "vocabulary": vocabulary,
            "label_weights": label_weights,
            "label_bias": label_bias,
            "category_weights": category_weights,
            "category_bias": category_bias,
            "temperature": 1.8,
        }) if validation else {},
    }
    return model


def evaluate_semantic_model(examples: list[SemanticExample], model: dict[str, Any]) -> dict[str, Any]:
    confusion: dict[str, Counter[str]] = {label: Counter() for label in LABELS}
    category_total = 0
    category_correct = 0
    records: list[dict[str, Any]] = []
    for example in examples:
        prediction = predict_files(example.files, model)
        confusion[example.label][prediction.label] += 1
        if example.category and example.category != "BENIGN":
            category_total += 1
            if prediction.category == example.category:
                category_correct += 1
        records.append(
            {
                "name": example.name,
                "label": example.label,
                "prediction": prediction.label,
                "confidence": round(prediction.confidence, 4),
                "category": example.category,
                "predicted_category": prediction.category,
            }
        )

    tp = confusion["malicious"]["malicious"]
    fn = sum(confusion["malicious"][label] for label in LABELS if label != "malicious")
    fp = sum(confusion[label]["malicious"] for label in LABELS if label != "malicious")
    total = len(examples)
    correct = sum(confusion[label][label] for label in LABELS)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    beta2 = 4.0
    f2 = (1 + beta2) * precision * recall / (beta2 * precision + recall) if precision + recall else 0.0
    return {
        "total": total,
        "accuracy": round(correct / total, 4) if total else 0.0,
        "precision_malicious": round(precision, 4),
        "recall_malicious": round(recall, 4),
        "f2_malicious": round(f2, 4),
        "false_negatives": int(fn),
        "false_positives": int(fp),
        "category_accuracy": round(category_correct / category_total, 4) if category_total else 0.0,
        "confusion": {label: dict(confusion[label]) for label in LABELS},
        "records": records,
    }


def load_semantic_examples(manifest_path: Path, options: ScanOptions | None = None) -> list[SemanticExample]:
    options = options or ScanOptions(use_policy=False)
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    examples: list[SemanticExample] = []
    for item in manifest:
        path = root / item["path"]
        examples.append(
            SemanticExample(
                name=str(item.get("name", path.name)),
                label=str(item["label"]),
                category=str(item.get("category", "BENIGN")),
                files=collect_files(path, options),
                source=str(item.get("source", manifest_path.name)),
            )
        )
    return examples


def split_examples(
    examples: list[SemanticExample],
    *,
    validation_ratio: float,
    seed: int,
) -> tuple[list[SemanticExample], list[SemanticExample]]:
    if not examples or validation_ratio <= 0:
        return list(examples), []
    validation_names: set[str] = set()
    by_label: dict[str, list[SemanticExample]] = defaultdict(list)
    for example in examples:
        by_label[example.label].append(example)
    for label, items in by_label.items():
        if len(items) < 2:
            continue
        holdout = max(1, math.ceil(len(items) * validation_ratio))
        holdout = min(holdout, len(items) - 1)
        ordered = sorted(items, key=lambda item: _split_key(item, seed))
        validation_names.update(item.name for item in ordered[:holdout])
    train = [example for example in examples if example.name not in validation_names]
    validation = [example for example in examples if example.name in validation_names]
    return train, validation


def select_vocabulary(examples: list[SemanticExample], *, max_features: int) -> list[str]:
    label_counts: dict[str, Counter[str]] = {label: Counter() for label in LABELS}
    document_counts: Counter[str] = Counter()
    for example in examples:
        counts = raw_features(example.files)
        label_counts.setdefault(example.label, Counter()).update({key: min(value, 4) for key, value in counts.items()})
        for key in counts:
            document_counts[key] += 1

    total_docs = max(1, len(examples))
    label_totals = {label: max(1, sum(counter.values())) for label, counter in label_counts.items()}
    global_total = max(1, sum(sum(counter.values()) for counter in label_counts.values()))
    scored: list[tuple[float, str]] = []
    for feature, doc_count in document_counts.items():
        if doc_count < 1:
            continue
        global_rate = sum(label_counts[label][feature] for label in label_counts) / global_total
        separation = sum(abs(label_counts[label][feature] / label_totals[label] - global_rate) for label in label_counts)
        idf = math.log(1.0 + total_docs / doc_count)
        scored.append((separation * idf, feature))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [feature for _, feature in scored[:max_features]]


def write_semantic_model(path: Path, model: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def train_semantic_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="skillmri train-semantic")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output-model", type=Path, default=DEFAULT_SEMANTIC_MODEL_PATH)
    parser.add_argument("--epochs", type=int, default=28)
    parser.add_argument("--max-features", type=int, default=900)
    parser.add_argument("--validation-ratio", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=23)
    args = parser.parse_args(argv)
    examples = load_semantic_examples(args.manifest)
    model = train_semantic_model(
        examples,
        epochs=args.epochs,
        max_features=args.max_features,
        validation_ratio=args.validation_ratio,
        seed=args.seed,
    )
    write_semantic_model(args.output_model, model)
    print(json.dumps({
        "output_model": str(args.output_model),
        "corpus_examples": model["corpus_examples"],
        "training_examples": model["training_examples"],
        "validation_examples": model["validation_examples"],
        "validation_metrics": model.get("validation_metrics", {}),
        "model_bytes": args.output_model.stat().st_size,
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _train_linear(
    train_vectors: list[tuple[SemanticExample, dict[str, float]]],
    labels: list[str],
    expected: Any,
    epochs: int,
    learning_rate: float,
    seed: int,
) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    weights: dict[str, dict[str, float]] = {label: {} for label in labels}
    bias: dict[str, float] = {label: 0.0 for label in labels}
    for epoch in range(epochs):
        ordered = sorted(train_vectors, key=lambda item: _split_key(item[0], seed + epoch))
        for example, features in ordered:
            gold = expected(example)
            if gold not in labels:
                continue
            prediction = max(labels, key=lambda label: bias[label] + sum(weights[label].get(name, 0.0) * value for name, value in features.items()))
            if prediction == gold:
                continue
            penalty = _mistake_penalty(gold, prediction)
            step = learning_rate * penalty
            bias[gold] += step
            bias[prediction] -= step
            for name, value in features.items():
                weights[gold][name] = weights[gold].get(name, 0.0) + step * value
                weights[prediction][name] = weights[prediction].get(name, 0.0) - step * value
    return weights, bias


def _tokens(text: str) -> list[str]:
    text = text.lower()
    text = re.sub(r"https?://", " urlscheme ", text)
    return [token.strip("._:-/") for token in TOKEN_RE.findall(text) if 2 <= len(token.strip("._:-/")) <= 48]


def _scores(features: dict[str, float], weights: dict[str, dict[str, float]], bias: dict[str, float]) -> dict[str, float]:
    labels = list(weights) or list(bias) or list(LABELS)
    return {
        label: float(bias.get(label, 0.0)) + sum(float(weights.get(label, {}).get(name, 0.0)) * value for name, value in features.items())
        for label in labels
    }


def _softmax(scores: dict[str, float], temperature: float) -> dict[str, float]:
    if not scores:
        return {}
    temperature = max(0.1, temperature)
    max_score = max(scores.values())
    exps = {label: math.exp((score - max_score) / temperature) for label, score in scores.items()}
    total = sum(exps.values()) or 1.0
    return {label: round(value / total, 4) for label, value in exps.items()}


def _top_with_margin(probabilities: dict[str, float]) -> tuple[str, float, float]:
    ordered = sorted(probabilities.items(), key=lambda item: item[1], reverse=True)
    if not ordered:
        return "benign", 0.0, 0.0
    top_label, top_score = ordered[0]
    runner_up = ordered[1][1] if len(ordered) > 1 else 0.0
    return top_label, top_score, top_score - runner_up


def _contributors(label: str, features: dict[str, float], weights: dict[str, float]) -> list[dict[str, Any]]:
    items = [
        {
            "feature": name,
            "value": round(value, 4),
            "weight": round(float(weights.get(name, 0.0)), 4),
            "impact": round(value * float(weights.get(name, 0.0)), 4),
        }
        for name, value in features.items()
        if abs(value * float(weights.get(name, 0.0))) > 0.0001
    ]
    items.sort(key=lambda item: abs(float(item["impact"])), reverse=True)
    return items[:8]


def _contest_internal_category(category: str, label: str) -> str:
    normalized = category.strip().upper().replace("-", "")
    if normalized == "BENIGN":
        return "AST-10"
    if re.fullmatch(r"AST[0-9]{2}", normalized):
        return f"AST-{normalized[-2:]}"
    return "AST-01" if label == "malicious" else "AST-10"


def _top_contributor_snippet(prediction: SemanticPrediction) -> str:
    if not prediction.contributors:
        return ""
    return ", ".join(str(item["feature"]) for item in prediction.contributors[:3])


def _mistake_penalty(expected: str, predicted: str) -> float:
    if expected == "malicious" and predicted != "malicious":
        return 4.0
    if expected != "malicious" and predicted == "malicious":
        return 2.0
    return 1.2


def _split_key(example: SemanticExample, seed: int) -> str:
    payload = f"{seed}|{example.name}|{example.label}|{example.category}|{example.source}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _rounded_weights(weights: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    return {
        label: {
            name: round(value, 6)
            for name, value in sorted(label_weights.items())
            if abs(value) > 0.000001
        }
        for label, label_weights in weights.items()
    }
