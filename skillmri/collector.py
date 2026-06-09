from __future__ import annotations

from pathlib import Path

from .schema import FileRecord, ScanOptions


BINARY_EXTENSIONS = {
    ".7z",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".dmg",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".lockb",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".tar",
    ".tgz",
    ".webp",
    ".zip",
}

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}


def collect_files(target: Path, options: ScanOptions) -> list[FileRecord]:
    target = target.resolve()
    if target.is_file():
        return [_read_file(target, target.parent, options)]

    records: list[FileRecord] = []
    for path in sorted(target.rglob("*")):
        if len(records) >= options.max_total_files:
            break
        if _is_ignored(path, target):
            continue
        if path.is_file():
            records.append(_read_file(path, target, options))
    return records


def _is_ignored(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in IGNORED_DIRS for part in rel_parts)


def _read_file(path: Path, root: Path, options: ScanOptions) -> FileRecord:
    relpath = path.relative_to(root).as_posix()
    is_binary = path.suffix.lower() in BINARY_EXTENSIONS
    raw = path.read_bytes()[: options.max_file_bytes]
    if not is_binary:
        is_binary = b"\x00" in raw[:4096]

    if is_binary:
        text = ""
    else:
        text = raw.decode("utf-8", errors="replace")

    return FileRecord(
        path=path,
        relpath=relpath,
        text=text,
        lines=text.splitlines(),
        is_binary=is_binary,
    )
