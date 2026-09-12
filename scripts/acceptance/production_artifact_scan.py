#!/usr/bin/env python3
"""Fail closed when production artifacts cross release boundaries."""

import pathlib
import stat
import tarfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN_SEGMENTS = {".git", "coverage", "node_modules", "public", "scripts", "src"}
ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip")
TAR_SUFFIXES = tuple(suffix for suffix in ARCHIVE_SUFFIXES if suffix != ".zip")


def validate_member(name: str) -> None:
    normalized = name.replace("\\", "/")
    member = pathlib.PurePosixPath(normalized)
    if member.is_absolute() or pathlib.PureWindowsPath(name).drive or ".." in member.parts:
        raise SystemExit(f"unsafe production artifact path: {name}")
    parts = tuple(part.lower() for part in member.parts if part not in ("", "."))
    if any(part in FORBIDDEN_SEGMENTS for part in parts):
        raise SystemExit(f"development-only path in production artifact: {name}")


def reject_nested_archive(name: str) -> None:
    if name.lower().endswith(ARCHIVE_SUFFIXES):
        raise SystemExit(f"nested archive in production artifact: {name}")


def inspect(path: pathlib.Path) -> int:
    if path.name.lower().endswith(TAR_SUFFIXES):
        count = 0
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                validate_member(member.name)
                if member.issym() or member.islnk():
                    raise SystemExit(f"link in production archive: {path}:{member.name}")
                if not member.isfile() and not member.isdir():
                    raise SystemExit(f"special file in production archive: {path}:{member.name}")
                if member.isfile():
                    reject_nested_archive(member.name)
                    count += 1
        return count
    if path.suffix.lower() == ".zip":
        count = 0
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                validate_member(member.filename)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if stat.S_ISLNK(mode):
                    raise SystemExit(f"symlink in production archive: {path}:{member.filename}")
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise SystemExit(f"special file in production archive: {path}:{member.filename}")
                if not member.is_dir():
                    reject_nested_archive(member.filename)
                    count += 1
        return count
    validate_member(path.name)
    return 1


def scan(root: pathlib.Path) -> int:
    seen = 0
    for directory in (root / "web/dist", root / "internal/webui/dist", root / "release"):
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            relative = path.relative_to(directory)
            validate_member(relative.as_posix())
            if path.is_symlink():
                raise SystemExit(f"symlink in production artifact tree: {path}")
            if path.is_file():
                if path.stat().st_nlink > 1:
                    raise SystemExit(f"hard link in production artifact tree: {path}")
                seen += inspect(path)
    if seen == 0:
        raise SystemExit("no production artifact directory found; scan cannot pass")
    build = (root / "scripts/ci/build-web.sh").read_text(encoding="utf-8")
    if "npm ci --no-audit --no-fund --ignore-scripts" not in build:
        raise SystemExit("production build must install from the lockfile without lifecycle scripts")
    return seen


if __name__ == "__main__":
    print(f"production artifact boundary scan passed ({scan(ROOT)} files)")
