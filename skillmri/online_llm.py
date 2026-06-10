from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .schema import Evidence, FileRecord, ScanOptions


DEFAULT_ONLINE_BASE_URL = "https://api.4022543.xyz/v1"
DEFAULT_ONLINE_MODEL = "gpt-5.5"
ENV_ONLINE_ENABLED = "SKILLMRI_ONLINE_CLASSIFIER"
ENV_ONLINE_API_KEY = "SKILLMRI_ONLINE_API_KEY"
ENV_ONLINE_BASE_URL = "SKILLMRI_ONLINE_BASE_URL"
ENV_ONLINE_MODEL = "SKILLMRI_ONLINE_MODEL"
ENV_ONLINE_TIMEOUT = "SKILLMRI_ONLINE_TIMEOUT_SECONDS"
ENV_ONLINE_MAX_CHARS = "SKILLMRI_ONLINE_MAX_PROMPT_CHARS"

SYSTEM_PROMPT = """You are a blue-team detector for Agent Skill packages.
Classify the skill as benign, suspicious, or malicious and assign one OWASP
Agentic Skills Top 10 main category from AST01 through AST10.

Return strict JSON only:
{"verdict":"benign|suspicious|malicious","confidence":0.0,"category":"AST01","rationale":"short evidence-based reason"}

Prefer recall for genuinely malicious skills, but do not mark normal docs,
examples, API clients, or security scanners malicious without concrete evidence.
"""

SECRET_REPLACEMENTS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]


def online_llm_evidence(
    files: list[FileRecord],
    evidence: list[Evidence],
    options: ScanOptions,
) -> tuple[list[Evidence], dict[str, Any]]:
    config = _online_config(options)
    if not config["enabled"]:
        return [], {"enabled": False, "reason": "disabled"}
    if not config["api_key"]:
        return [], {"enabled": False, "reason": f"missing {ENV_ONLINE_API_KEY}"}

    prompt = build_classifier_prompt(files, evidence, max_chars=config["max_prompt_chars"])
    started = time.perf_counter()
    try:
        content = _chat_completion(
            api_key=config["api_key"],
            base_url=config["base_url"],
            model=config["model"],
            prompt=prompt,
            timeout=config["timeout"],
        )
        parsed = parse_classifier_payload(content)
    except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc:
        return [], {
            "enabled": True,
            "model": config["model"],
            "base_url": config["base_url"],
            "request_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }

    parsed["request_ms"] = round((time.perf_counter() - started) * 1000, 2)
    parsed["model"] = config["model"]
    parsed["base_url"] = config["base_url"]
    hits = _prediction_to_evidence(parsed)
    return hits, {"enabled": True, **parsed}


def build_classifier_prompt(files: list[FileRecord], evidence: list[Evidence], *, max_chars: int = 20_000) -> str:
    parts: list[str] = []
    inventory = []
    for record in files[:120]:
        kind = "binary" if record.is_binary else "text"
        inventory.append(f"- {record.relpath} ({kind}, {len(record.text)} chars)")
    parts.append("FILES:\n" + "\n".join(inventory))

    if evidence:
        existing = []
        for item in evidence[:24]:
            existing.append(
                f"- {item.rule_id} {item.category} {item.severity} "
                f"{item.file}:{item.line} {item.message} snippet={_sanitize(item.snippet)[:180]}"
            )
        parts.append("STATIC_AND_LOCAL_EVIDENCE:\n" + "\n".join(existing))
    else:
        parts.append("STATIC_AND_LOCAL_EVIDENCE:\n- none")

    remaining = max(1000, max_chars - sum(len(part) for part in parts))
    snippets: list[str] = []
    for record in _prioritized_files(files):
        if remaining <= 0:
            break
        if record.is_binary or not record.text.strip():
            continue
        text = _sanitize(record.text)
        take = min(remaining, 4000 if _is_high_signal_path(record.relpath) else 1800)
        snippets.append(f"--- {record.relpath} ---\n{text[:take]}")
        remaining -= take
    parts.append("SKILL_CONTENT_SNIPPETS:\n" + "\n\n".join(snippets))
    return "\n\n".join(parts)[:max_chars]


def parse_classifier_payload(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    if "{" in text and "}" in text:
        text = text[text.find("{") : text.rfind("}") + 1]
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("classifier response is not a JSON object")

    verdict = str(payload.get("verdict", payload.get("label", ""))).strip().lower()
    if verdict not in {"benign", "suspicious", "malicious"}:
        raise ValueError(f"invalid classifier verdict: {verdict!r}")
    confidence = _clamp_float(payload.get("confidence", 0.0))
    category = normalize_online_category(str(payload.get("category", "AST10")))
    rationale = str(payload.get("rationale", payload.get("evidence", ""))).strip()
    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "category": category,
        "rationale": rationale[:500],
    }


def normalize_online_category(category: str) -> str:
    normalized = category.strip().upper().replace("-", "")
    if normalized.startswith("AST") and normalized[3:].isdigit():
        number = int(normalized[3:])
        if 1 <= number <= 10:
            return f"AST-{number:02d}"
    return "AST-10"


def _prediction_to_evidence(parsed: dict[str, Any]) -> list[Evidence]:
    verdict = parsed["verdict"]
    confidence = float(parsed["confidence"])
    category = parsed["category"]
    rationale = parsed.get("rationale") or "No rationale returned."
    if verdict == "malicious" and confidence >= 0.68:
        return [
            Evidence(
                file="online://classifier",
                line=1,
                message=f"Online LLM classifier predicts malicious behavior (confidence={confidence:.3f}, category={category}).",
                snippet=rationale,
                category=category,
                severity="critical",
                rule_id="online-llm-malicious",
                weight=0.7,
            )
        ]
    if verdict == "suspicious" and confidence >= 0.62:
        return [
            Evidence(
                file="online://classifier",
                line=1,
                message=f"Online LLM classifier predicts suspicious behavior (confidence={confidence:.3f}, category={category}).",
                snippet=rationale,
                category=category,
                severity="medium",
                rule_id="online-llm-suspicious",
                weight=0.45,
            )
        ]
    return []


def _chat_completion(*, api_key: str, base_url: str, model: str, prompt: str, timeout: float) -> str:
    url = _chat_completions_url(base_url)
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 300,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SkillMRI/online-classifier",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    try:
        return str(payload["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"unexpected chat completion response: {payload!r}") from exc


def _chat_completions_url(base_url: str) -> str:
    cleaned = base_url.strip().rstrip("/")
    if cleaned.endswith("/chat/completions"):
        return cleaned
    return f"{cleaned}/chat/completions"


def _online_config(options: ScanOptions) -> dict[str, Any]:
    return {
        "enabled": options.use_online_classifier or _truthy(os.environ.get(ENV_ONLINE_ENABLED)),
        "api_key": options.online_api_key or os.environ.get(ENV_ONLINE_API_KEY, ""),
        "base_url": (options.online_base_url or os.environ.get(ENV_ONLINE_BASE_URL) or DEFAULT_ONLINE_BASE_URL).strip(),
        "model": (options.online_model or os.environ.get(ENV_ONLINE_MODEL) or DEFAULT_ONLINE_MODEL).strip(),
        "timeout": _float_env(ENV_ONLINE_TIMEOUT, options.online_timeout_seconds),
        "max_prompt_chars": _int_env(ENV_ONLINE_MAX_CHARS, options.online_max_prompt_chars),
    }


def _prioritized_files(files: list[FileRecord]) -> list[FileRecord]:
    return sorted(files, key=lambda record: (0 if _is_high_signal_path(record.relpath) else 1, record.relpath))


def _is_high_signal_path(relpath: str) -> bool:
    name = Path(relpath).name.lower()
    return name in {"skill.md", "readme.md", "manifest.json", "skill.json", "agents.md"} or name.endswith((".py", ".js", ".ts", ".sh"))


def _sanitize(text: str) -> str:
    sanitized = text.replace("\x00", "")
    for pattern in SECRET_REPLACEMENTS:
        sanitized = pattern.sub("<redacted-secret>", sanitized)
    return sanitized


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _float_env(name: str, default: float) -> float:
    try:
        return max(0.2, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return max(1000, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _clamp_float(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = 0.0
    return min(1.0, max(0.0, parsed))
