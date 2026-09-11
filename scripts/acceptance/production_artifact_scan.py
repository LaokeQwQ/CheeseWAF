#!/usr/bin/env python3
"""Fail-closed scan for production web and release artifacts."""
import pathlib
import tarfile
import zipfile
import gzip

ROOT = pathlib.Path(__file__).resolve().parents[2]
MARKERS = (b"agent-eyes", b"code-inspector", b"codex-acp")
seen = 0

def check(name, data):
    for marker in MARKERS:
        if marker in data.lower():
            raise SystemExit(f"forbidden production marker {marker.decode()} in {name}")

def inspect(path):
    global seen
    seen += 1
    if path.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile():
                    check(f"{path}:{member.name}", archive.extractfile(member).read())
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if not member.is_dir():
                    check(f"{path}:{member.filename}", archive.read(member))
    elif path.suffix == ".gz":
        with gzip.open(path, "rb") as stream:
            check(path, stream.read())
    else:
        check(path, path.read_bytes())

def scan(root):
    global seen
    seen = 0
    for directory in (root / "web/dist", root / "internal/webui/dist", root / "release"):
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_symlink():
                    raise SystemExit(f"symlink in production artifact tree: {path}")
                if path.is_file():
                    inspect(path)
    if seen == 0:
        raise SystemExit("no production artifact directory found; scan cannot pass")
    build = (root / "scripts/ci/build-web.sh").read_text(encoding="utf-8")
    if "CHEESEWAF_AGENT_EYES=0" not in build or "npm ci --no-audit --no-fund --ignore-scripts" not in build:
        raise SystemExit("production build does not disable Agent tooling")
    return seen

if __name__ == "__main__":
    print(f"production artifact marker scan passed ({scan(ROOT)} files)")
