"""Fetch and bundle an npm package for analysis.

Pulls registry metadata + tarball, extracts in a temp dir, and returns a
``PackageBundle`` with: package.json, JS/TS source files (capped), maintainer
metadata, and lifecycle scripts. Optionally fetches the previous version for
diffing.
"""
from __future__ import annotations

import io
import json
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

REGISTRY = "https://registry.npmjs.org"
SOURCE_EXTS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
MAX_FILES = 100
MAX_TOTAL_CHARS = 200_000
MAX_FILE_CHARS = 40_000

# Patterns that bump a file's priority when we have to sample.
SUSPICIOUS_HINTS = (
    "eval(", "Function(", "child_process", "exec(",
    "spawn(", "require('http", 'require("http',
    "fetch(", "atob(", "Buffer.from", "process.env",
    "crypto.create", "fs.readFileSync", "fs.writeFile",
    ".onload", "preinstall", "postinstall",
    # heavy obfuscation markers
    "\\x", "_0x", "decodeURIComponent",
)


@dataclass
class PackageBundle:
    name: str
    version: str
    package_json: dict
    files: dict[str, str] = field(default_factory=dict)  # path -> content
    maintainers: list[dict] = field(default_factory=list)
    author: Optional[str] = None
    description: Optional[str] = None
    published_at: Optional[str] = None
    publisher: Optional[dict] = None
    previous_version: Optional[str] = None
    total_size_bytes: int = 0
    truncated_files: int = 0
    sample_note: str = ""

    @property
    def lifecycle_scripts(self) -> dict[str, str]:
        scripts = self.package_json.get("scripts", {}) or {}
        risky_keys = {"preinstall", "install", "postinstall",
                      "preuninstall", "uninstall", "postuninstall",
                      "prepublish", "prepare"}
        return {k: v for k, v in scripts.items() if k in risky_keys}

    @property
    def dependencies(self) -> dict[str, str]:
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(self.package_json.get(key, {}) or {})
        return deps


async def _fetch_metadata(client: httpx.AsyncClient, name: str) -> dict:
    r = await client.get(f"{REGISTRY}/{name}", timeout=30)
    r.raise_for_status()
    return r.json()


async def _fetch_tarball(client: httpx.AsyncClient, url: str) -> bytes:
    r = await client.get(url, timeout=60, follow_redirects=True)
    r.raise_for_status()
    return r.content


def _is_source(path: str) -> bool:
    return Path(path).suffix.lower() in SOURCE_EXTS


def _priority(path: str, content: str) -> int:
    """Lower = higher priority. Always include package.json + lifecycle scripts."""
    name = Path(path).name.lower()
    if name == "package.json":
        return 0
    hints = sum(1 for h in SUSPICIOUS_HINTS if h in content)
    base = 5 if hints else 10
    # short files first to maximize coverage within the cap
    return base - min(hints, 4) + min(len(content) // 5000, 4)


def _extract(tarball_bytes: bytes) -> tuple[dict, dict[str, str], int]:
    """Returns (package_json, source_files, total_bytes_seen)."""
    pkg_json = {}
    raw_files: list[tuple[str, str]] = []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            # npm tarballs nest everything under "package/"
            rel = member.name.removeprefix("package/")
            total += member.size
            f = tar.extractfile(member)
            if f is None:
                continue
            try:
                data = f.read()
            except Exception:
                continue
            if rel == "package.json":
                try:
                    pkg_json = json.loads(data)
                except json.JSONDecodeError:
                    pkg_json = {}
                continue
            if not _is_source(rel):
                continue
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                continue
            if len(text) > MAX_FILE_CHARS:
                text = text[:MAX_FILE_CHARS] + f"\n/* ... truncated, original {len(text)} chars */"
            raw_files.append((rel, text))
    return pkg_json, dict(raw_files), total


def _sample(files: dict[str, str]) -> tuple[dict[str, str], int, str]:
    """Cap files by MAX_FILES and MAX_TOTAL_CHARS using priority."""
    ranked = sorted(files.items(), key=lambda kv: _priority(*kv))
    out: dict[str, str] = {}
    used = 0
    for path, content in ranked:
        if len(out) >= MAX_FILES:
            break
        if used + len(content) > MAX_TOTAL_CHARS:
            continue
        out[path] = content
        used += len(content)
    dropped = len(files) - len(out)
    note = ""
    if dropped > 0:
        note = (f"Sampled {len(out)}/{len(files)} source files by suspicion priority "
                f"({used:,} chars within {MAX_TOTAL_CHARS:,} cap).")
    return out, dropped, note


async def fetch_package(name: str, version: str = "latest") -> PackageBundle:
    """Download a single npm package version and return a PackageBundle."""
    async with httpx.AsyncClient() as client:
        meta = await _fetch_metadata(client, name)

        if version == "latest":
            version = meta.get("dist-tags", {}).get("latest", "")
            if not version:
                raise RuntimeError(f"could not resolve latest version of {name}")

        if version not in meta.get("versions", {}):
            raise RuntimeError(f"version {version} not found for {name}")

        version_meta = meta["versions"][version]
        tarball_url = version_meta.get("dist", {}).get("tarball")
        if not tarball_url:
            raise RuntimeError(f"no tarball url for {name}@{version}")

        tarball = await _fetch_tarball(client, tarball_url)

    pkg_json, files, total_bytes = _extract(tarball)
    sampled, dropped, note = _sample(files)

    published_at = meta.get("time", {}).get(version)
    publisher = None
    for entry in meta.get("_npmUser", []) if False else []:
        publisher = entry
        break
    # _npmUser is per-version in the version manifest, not top-level
    publisher = version_meta.get("_npmUser")

    return PackageBundle(
        name=name,
        version=version,
        package_json=pkg_json,
        files=sampled,
        maintainers=meta.get("maintainers", []) or [],
        author=(meta.get("author") or {}).get("name") if isinstance(meta.get("author"), dict) else meta.get("author"),
        description=meta.get("description"),
        published_at=published_at,
        publisher=publisher,
        total_size_bytes=total_bytes,
        truncated_files=dropped,
        sample_note=note,
    )


def fetch_local(path: str | Path) -> PackageBundle:
    """Build a ``PackageBundle`` from a local directory containing package.json.

    Useful for scanning your own package before publishing, or for testing on
    synthetic fixtures.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise RuntimeError(f"not a directory: {root}")

    pj_path = root / "package.json"
    if not pj_path.is_file():
        raise RuntimeError(f"no package.json at {root}")

    try:
        pkg_json = json.loads(pj_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"invalid package.json: {e}") from e

    raw_files: dict[str, str] = {}
    total = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        if rel == "package.json":
            continue
        if not _is_source(rel):
            continue
        # skip node_modules, .git, etc.
        if any(part in {"node_modules", ".git", "dist", "build"} for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        total += p.stat().st_size
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + f"\n/* ... truncated, original {len(text)} chars */"
        raw_files[rel] = text

    sampled, dropped, note = _sample(raw_files)

    return PackageBundle(
        name=pkg_json.get("name", root.name),
        version=pkg_json.get("version", "0.0.0-local"),
        package_json=pkg_json,
        files=sampled,
        maintainers=[],
        author=(pkg_json.get("author") or {}).get("name") if isinstance(pkg_json.get("author"), dict) else pkg_json.get("author"),
        description=pkg_json.get("description"),
        published_at="(local)",
        publisher=None,
        total_size_bytes=total,
        truncated_files=dropped,
        sample_note=note,
    )


async def fetch_with_previous(name: str, version: str) -> tuple[PackageBundle, Optional[PackageBundle]]:
    """Fetch the requested version and the most recent prior version (if any)."""
    async with httpx.AsyncClient() as client:
        meta = await _fetch_metadata(client, name)

    if version == "latest":
        version = meta["dist-tags"]["latest"]

    versions = list(meta.get("versions", {}).keys())
    prev = None
    if version in versions:
        idx = versions.index(version)
        if idx > 0:
            prev = versions[idx - 1]

    current = await fetch_package(name, version)
    previous = await fetch_package(name, prev) if prev else None
    if previous:
        current.previous_version = prev
    return current, previous
