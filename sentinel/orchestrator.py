"""End-to-end scan: fetch package -> fan out agents -> judge -> format report."""
from __future__ import annotations

import json
from typing import Any

from .agents import run_all_agents
from .fetcher import fetch_local, fetch_package
from .judge import run_judge

VERDICT_COLORS = {
    "clean": "\033[32m",      # green
    "suspicious": "\033[33m",  # yellow
    "malicious": "\033[31m",   # red
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _color_verdict(verdict: str) -> str:
    color = VERDICT_COLORS.get(verdict, "")
    return f"{color}{BOLD}{verdict.upper()}{RESET}"


def _format_finding(f: dict) -> str:
    flagged = ", ".join(f.get("flagged_by", []))
    loc = f.get("file") or "(metadata)"
    sev = f["severity"].upper()
    return (
        f"  [{sev}] {f['category']} — {loc}\n"
        f"    evidence: {f['evidence']}\n"
        f"    flagged by: {flagged}"
    )


def format_report(bundle_name: str, version: str, verdict: dict, agent_results: list[dict]) -> str:
    parts = [
        "",
        f"{BOLD}╔══════════════════════════════════════════════════════════════════╗{RESET}",
        f"{BOLD}║  pkg-sentinel scan: {bundle_name}@{version}".ljust(75) + f"{BOLD}║{RESET}",
        f"{BOLD}╚══════════════════════════════════════════════════════════════════╝{RESET}",
        "",
        f"Verdict:    {_color_verdict(verdict['verdict'])} (confidence: {verdict['confidence']})",
        f"Headline:   {verdict['headline']}",
        "",
        f"{BOLD}Reasoning{RESET}",
        f"  {verdict['reasoning']}",
    ]

    if verdict.get("top_findings"):
        parts.append("")
        parts.append(f"{BOLD}Top findings{RESET}")
        for f in verdict["top_findings"]:
            parts.append(_format_finding(f))

    parts.append("")
    parts.append(f"{BOLD}Per-agent summary{RESET}")
    for r in agent_results:
        n = len(r["findings"])
        marker = "·" if n == 0 else "!"
        parts.append(f"  {marker} {r['name']:>16} — {n} finding(s)  {DIM}{r.get('summary', '')}{RESET}")

    cache_read = sum(r["usage"]["cache_read_input_tokens"] for r in agent_results)
    cache_write = sum(r["usage"]["cache_creation_input_tokens"] for r in agent_results)
    total_in = sum(r["usage"]["input_tokens"] for r in agent_results)
    total_out = sum(r["usage"]["output_tokens"] for r in agent_results)

    parts.append("")
    parts.append(
        f"{DIM}tokens: agents in={total_in} out={total_out} "
        f"cache_write={cache_write} cache_read={cache_read} · "
        f"judge in={verdict['_usage']['input_tokens']} out={verdict['_usage']['output_tokens']}{RESET}"
    )
    return "\n".join(parts)


def _result_from_bundle(bundle, agent_results, verdict) -> dict[str, Any]:
    return {
        "name": bundle.name,
        "version": bundle.version,
        "verdict": verdict,
        "agent_results": agent_results,
        "bundle": {
            "files": list(bundle.files.keys()),
            "lifecycle_scripts": bundle.lifecycle_scripts,
            "maintainers": bundle.maintainers,
            "publisher": bundle.publisher,
            "published_at": bundle.published_at,
        },
    }


async def scan_package(name: str, version: str = "latest") -> dict[str, Any]:
    bundle = await fetch_package(name, version)
    agent_results = await run_all_agents(bundle)
    verdict = await run_judge(agent_results)
    return _result_from_bundle(bundle, agent_results, verdict)


async def scan_local_path(path: str) -> dict[str, Any]:
    bundle = fetch_local(path)
    agent_results = await run_all_agents(bundle)
    verdict = await run_judge(agent_results)
    return _result_from_bundle(bundle, agent_results, verdict)


def to_json(result: dict[str, Any]) -> str:
    """Return a JSON-serializable view of a scan result."""
    out = {
        "name": result["name"],
        "version": result["version"],
        "verdict": {k: v for k, v in result["verdict"].items() if k != "_usage"},
        "agents": [
            {
                "name": r["name"],
                "summary": r.get("summary", ""),
                "findings": r["findings"],
            }
            for r in result["agent_results"]
        ],
        "bundle": result["bundle"],
    }
    return json.dumps(out, indent=2, default=str)
