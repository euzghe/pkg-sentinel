"""sentinel CLI — scan an npm package for supply-chain attack signals."""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from .agents import AGENTS, _build_system
from .fetcher import fetch_local, fetch_package
from .orchestrator import format_report, scan_local_path, scan_package, to_json


def _load_dotenv() -> None:
    """Tiny .env loader (no dependency on python-dotenv)."""
    for path in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _parse_spec(spec: str) -> tuple[str, str]:
    """Parse 'pkg' or 'pkg@version' or '@scope/pkg@version'."""
    if spec.startswith("@"):
        # scoped — split on second '@'
        scope_end = spec.find("/")
        rest = spec[scope_end:]
        at = rest.find("@")
        if at == -1:
            return spec, "latest"
        return spec[: scope_end] + rest[:at], rest[at + 1:]
    if "@" in spec:
        name, _, ver = spec.partition("@")
        return name, ver or "latest"
    return spec, "latest"


def _do_dry_run(args) -> int:
    """Fetch the bundle, build the prompts, print them — but do not call the LLM."""
    try:
        if args.cmd == "scan":
            name, version = _parse_spec(args.spec)
            bundle = asyncio.run(fetch_package(name, version))
        else:
            bundle = fetch_local(args.path)
    except Exception as e:
        print(f"error: fetch failed: {e}", file=sys.stderr)
        return 2

    system_blocks = _build_system(bundle)
    system_text = system_blocks[0]["text"]
    sys_chars = len(system_text)

    print(f"\n=== DRY RUN: {bundle.name}@{bundle.version} ===\n")
    print(f"Bundle stats:")
    print(f"  source files: {len(bundle.files)}")
    print(f"  tarball size: {bundle.total_size_bytes:,} bytes")
    print(f"  lifecycle scripts: {list(bundle.lifecycle_scripts.keys()) or 'none'}")
    print(f"  maintainers: {[m.get('name') for m in bundle.maintainers] or 'none'}")
    print(f"  publisher: {(bundle.publisher or {}).get('name', 'unknown')}")
    print()
    print(f"Shared system prompt (cached, sent ONCE, reused by all 5 agents):")
    print(f"  total chars: {sys_chars:,}")
    print(f"  est tokens:  ~{sys_chars // 4:,}")
    print()
    print(f"Agents that would fan out in parallel ({len(AGENTS)}):")
    for spec in AGENTS:
        focus_chars = len(spec.focus_prompt)
        print(f"  • {spec.name:>16}  ({focus_chars} chars of focus prompt)")
    print()
    print(f"Expected cost on first call:")
    print(f"  agent 1: cache_write ~{sys_chars // 4:,} tokens (1.25x)")
    print(f"  agents 2-5: cache_read ~{sys_chars // 4:,} tokens each (0.1x)")
    print(f"  judge: small payload (analyst findings only)")
    print()
    print("Add ANTHROPIC_API_KEY to .env and drop --dry-run to run for real.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Multi-agent supply chain attack scanner for npm packages.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan an npm package version from the registry")
    scan.add_argument("spec", help="Package spec: pkg, pkg@version, or @scope/pkg@version")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    scan.add_argument(
        "--exit-on", choices=["malicious", "suspicious"], default=None,
        help="Exit with code 1 if verdict is at or above this severity",
    )
    scan.add_argument(
        "--dry-run", action="store_true",
        help="Fetch + build prompts but do not call the LLM (no API key needed)",
    )

    scan_local = sub.add_parser("scan-local", help="Scan a local package directory (pre-publish or test fixture)")
    scan_local.add_argument("path", help="Directory containing package.json")
    scan_local.add_argument("--json", action="store_true")
    scan_local.add_argument("--exit-on", choices=["malicious", "suspicious"], default=None)
    scan_local.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    _load_dotenv()

    if args.dry_run:
        return _do_dry_run(args)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY is not set. Add it to .env or your shell.", file=sys.stderr)
        print("       (or use --dry-run to see what would be sent to the agents)", file=sys.stderr)
        return 2

    try:
        if args.cmd == "scan":
            name, version = _parse_spec(args.spec)
            result = asyncio.run(scan_package(name, version))
            display_name = name
        else:  # scan-local
            result = asyncio.run(scan_local_path(args.path))
            display_name = result["name"]
    except Exception as e:
        print(f"error: scan failed: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(to_json(result))
    else:
        print(format_report(display_name, result["version"], result["verdict"], result["agent_results"]))

    if args.exit_on:
        order = {"clean": 0, "suspicious": 1, "malicious": 2}
        threshold = order[args.exit_on]
        if order.get(result["verdict"]["verdict"], 0) >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
