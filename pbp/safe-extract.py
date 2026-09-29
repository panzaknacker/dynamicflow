#!/usr/bin/env python3
"""extract a trusted-by-hash archive without trusting its member paths."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
from typing import BinaryIO, Iterable, NamedTuple
import zipfile


class ArchiveError(RuntimeError):
    pass


class Entry(NamedTuple):
    name: str
    parts: tuple[str, ...]
    is_dir: bool
    size: int
    mode: int
    source: object


def safe_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        raise ArchiveError(f"unsafe archive path: {name!r}")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ArchiveError(f"control character in archive path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute():
        raise ArchiveError(f"absolute archive path: {name!r}")
    parts = tuple(part for part in path.parts if part != ".")
    if not parts or any(part in ("", "..") for part in parts):
        raise ArchiveError(f"traversing archive path: {name!r}")
    return parts


def checked_entries(entries: Iterable[Entry], max_bytes: int) -> list[Entry]:
    result: list[Entry] = []
    names: set[tuple[str, ...]] = set()
    total = 0
    for entry in entries:
        key = entry.parts
        if key in names:
            raise ArchiveError(f"duplicate archive path: {entry.name!r}")
        names.add(key)
        total += entry.size
        if total > max_bytes:
            raise ArchiveError("archive exceeds the uncompressed size limit")
        result.append(entry)
    return result


def zip_entries(archive: zipfile.ZipFile) -> list[Entry]:
    result: list[Entry] = []
    for info in archive.infolist():
        parts = safe_parts(info.filename)
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        is_dir = info.is_dir()
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ArchiveError(f"unsupported zip member type: {info.filename!r}")
        if file_type == stat.S_IFDIR and not is_dir:
            raise ArchiveError(f"inconsistent zip directory: {info.filename!r}")
        mode = unix_mode & 0o777
        result.append(Entry(info.filename, parts, is_dir, 0 if is_dir else info.file_size, mode, info))
    return result


def tar_entries(archive: tarfile.TarFile) -> list[Entry]:
    result: list[Entry] = []
    for member in archive.getmembers():
        parts = safe_parts(member.name)
        if not (member.isfile() or member.isdir()):
            raise ArchiveError(f"unsupported tar member type: {member.name!r}")
        result.append(
            Entry(
                member.name,
                parts,
                member.isdir(),
                0 if member.isdir() else member.size,
                member.mode & 0o777,
                member,
            )
        )
    return result


def destination_for(root: Path, parts: tuple[str, ...]) -> Path:
    destination = root.joinpath(*parts)
    if destination.parent != root:
        current = root
        for part in parts[:-1]:
            current = current / part
            if current.exists():
                if current.is_symlink() or not current.is_dir():
                    raise ArchiveError(f"unsafe extraction parent: {current}")
            else:
                current.mkdir(mode=0o755)
                os.chmod(current, 0o755, follow_symlinks=False)
    return destination


def write_file(destination: Path, source: BinaryIO, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    final_mode = 0o755 if mode & 0o111 else 0o644
    descriptor = os.open(destination, flags, final_mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    os.chmod(destination, final_mode, follow_symlinks=False)


def prepare_root(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"destination is not a real directory: {root}")
    if any(root.iterdir()):
        raise ArchiveError(f"destination is not empty: {root}")


def extract_zip(source: Path, root: Path, max_bytes: int) -> None:
    with zipfile.ZipFile(source) as archive:
        entries = checked_entries(zip_entries(archive), max_bytes)
        for entry in sorted((item for item in entries if item.is_dir), key=lambda item: len(item.parts)):
            destination = destination_for(root, entry.parts)
            destination.mkdir(mode=0o755, exist_ok=True)
            if destination.is_symlink() or not destination.is_dir():
                raise ArchiveError(f"unsafe extracted directory: {destination}")
            os.chmod(destination, 0o755, follow_symlinks=False)
        for entry in (item for item in entries if not item.is_dir):
            destination = destination_for(root, entry.parts)
            with archive.open(entry.source, "r") as payload:
                write_file(destination, payload, entry.mode)


def extract_tar(source: Path, root: Path, max_bytes: int) -> None:
    with tarfile.open(source, mode="r:*") as archive:
        entries = checked_entries(tar_entries(archive), max_bytes)
        for entry in sorted((item for item in entries if item.is_dir), key=lambda item: len(item.parts)):
            destination = destination_for(root, entry.parts)
            destination.mkdir(mode=0o755, exist_ok=True)
            if destination.is_symlink() or not destination.is_dir():
                raise ArchiveError(f"unsafe extracted directory: {destination}")
            os.chmod(destination, 0o755, follow_symlinks=False)
        for entry in (item for item in entries if not item.is_dir):
            destination = destination_for(root, entry.parts)
            payload = archive.extractfile(entry.source)
            if payload is None:
                raise ArchiveError(f"could not read tar member: {entry.name!r}")
            with payload:
                write_file(destination, payload, entry.mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("zip", "tar"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--max-bytes", type=int, required=True)
    args = parser.parse_args()
    if args.max_bytes < 1:
        parser.error("--max-bytes must be positive")
    if args.source.is_symlink() or not args.source.is_file():
        raise ArchiveError(f"source is not a real file: {args.source}")
    prepare_root(args.destination)
    if args.kind == "zip":
        extract_zip(args.source, args.destination, args.max_bytes)
    else:
        extract_tar(args.source, args.destination, args.max_bytes)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArchiveError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit(f"safe-extract: {error}") from error
