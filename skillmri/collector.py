from __future__ import annotations

import tarfile
import zipfile
from io import BytesIO
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
    ".onnx",
    ".pdf",
    ".png",
    ".pkl",
    ".pth",
    ".pt",
    ".pyc",
    ".safetensors",
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
        record = _read_file(target, target.parent, options)
        records = [record]
        if _is_archive(target):
            records.extend(_archive_records(target, target.parent, options, options.max_total_files - 1))
        return records

    records: list[FileRecord] = []
    for path in sorted(target.rglob("*")):
        if len(records) >= options.max_total_files:
            break
        if _is_ignored(path, target):
            continue
        if path.is_file():
            record = _read_file(path, target, options)
            records.append(record)
            if _is_archive(path):
                remaining = options.max_total_files - len(records)
                records.extend(_archive_records(path, target, options, remaining))
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


def _is_archive(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".zip", ".tar", ".tgz", ".tar.gz", ".gz"))


def _archive_records(path: Path, root: Path, options: ScanOptions, limit: int) -> list[FileRecord]:
    if limit <= 0:
        return []
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    records: list[FileRecord] = []
    if zipfile.is_zipfile(BytesIO(raw)):
        records.extend(_zip_records(path, root, raw, options, limit))
    elif tarfile.is_tarfile(path):
        records.extend(_tar_records(path, root, raw, options, limit))
    return records


def _zip_records(path: Path, root: Path, raw: bytes, options: ScanOptions, limit: int) -> list[FileRecord]:
    records: list[FileRecord] = []
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            for info in archive.infolist():
                if len(records) >= min(options.max_archive_members, limit):
                    break
                if info.is_dir() or _unsafe_archive_name(info.filename):
                    continue
                if info.file_size > options.max_archive_file_bytes:
                    continue
                try:
                    member_raw = archive.read(info, pwd=None)[: options.max_archive_file_bytes]
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                records.append(_virtual_record(path, root, info.filename, member_raw, options))
    except (OSError, zipfile.BadZipFile):
        return []
    return records


def _tar_records(path: Path, root: Path, raw: bytes, options: ScanOptions, limit: int) -> list[FileRecord]:
    records: list[FileRecord] = []
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                if len(records) >= min(options.max_archive_members, limit):
                    break
                if not member.isfile() or _unsafe_archive_name(member.name):
                    continue
                if member.size > options.max_archive_file_bytes:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                try:
                    member_raw = handle.read(options.max_archive_file_bytes)
                except OSError:
                    continue
                records.append(_virtual_record(path, root, member.name, member_raw, options))
    except (OSError, tarfile.TarError):
        return []
    return records


def _virtual_record(path: Path, root: Path, member_name: str, raw: bytes, options: ScanOptions) -> FileRecord:
    archive_relpath = path.relative_to(root).as_posix()
    relpath = f"{archive_relpath}!{member_name}"
    suffix = Path(member_name).suffix.lower()
    is_binary = suffix in BINARY_EXTENSIONS or b"\x00" in raw[:4096]
    text = "" if is_binary else raw[: options.max_archive_file_bytes].decode("utf-8", errors="replace")
    return FileRecord(
        path=Path(member_name),
        relpath=relpath,
        text=text,
        lines=text.splitlines(),
        is_binary=is_binary,
    )


def _unsafe_archive_name(name: str) -> bool:
    parts = Path(name.replace("\\", "/")).parts
    return not parts or any(part in {"", ".", ".."} for part in parts) or name.startswith(("/", "\\"))
