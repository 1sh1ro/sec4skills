from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Evidence:
    file: str
    line: int
    message: str
    snippet: str = ""
    category: str = "AST-UNKNOWN"
    severity: str = "medium"
    rule_id: str = "generic"
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
            "category": self.category,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "weight": self.weight,
        }


@dataclass
class FileRecord:
    path: Path
    relpath: str
    text: str
    lines: list[str]
    is_binary: bool = False


@dataclass
class ScanContext:
    target: Path
    files: list[FileRecord]
    declared_text: str = ""
    manifest_text: str = ""
    declared_capabilities: set[str] = field(default_factory=set)
    negative_declarations: set[str] = field(default_factory=set)
    actual_capabilities: set[str] = field(default_factory=set)
    evidence: list[Evidence] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanOptions:
    max_file_bytes: int = 1_000_000
    max_total_files: int = 2500
    sandbox: str = "off"
    output: str = "json"
    fail_on_malicious: bool = False
    use_policy: bool = True
    policy_path: Path | None = None
