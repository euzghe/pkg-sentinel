"""Sentinel agents.

Five specialized Claude agents fan out over the same package bundle. The
shared system prompt (package metadata + lifecycle scripts + source files) is
sent once and reused across all agents via ``cache_control: ephemeral``. Each
agent contributes a single facet of the malware verdict; the judge merges them.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import anthropic

from .fetcher import PackageBundle

MODEL = "claude-opus-4-7"
MAX_TOKENS = 8000

SYSTEM_TEMPLATE = """You are a senior security analyst on a supply-chain attack detection team.

You will be given:
  1. Full context of an npm package version (metadata + source files) in this system prompt.
  2. A specific analytical focus (in the user message).

Be precise. Cite file paths and the specific code or metadata that supports each finding.
Only flag REAL signals — do not invent risks. If nothing is suspicious in your focus area,
return an empty findings list. False alarms erode trust in the system.

Severity guide:
  - "critical": active malware behavior with high confidence (data exfil, backdoor, crypto-miner, dropper)
  - "high": clear malicious intent or extremely high-risk pattern (eval of remote payload, install-time exfil)
  - "medium": suspicious but ambiguous (obfuscation without clear purpose, network call to obscure host)
  - "low": worth noting but likely benign (telemetry, minor sloppiness)

PACKAGE CONTEXT
===============
Name:           {name}
Version:        {version}
Previous:       {previous}
Published:      {published_at}
Description:    {description}
Author:         {author}
Maintainers:    {maintainers}
Publisher (this version): {publisher}
Total tarball:  {total_size} bytes
Dependencies:   {dependencies}

LIFECYCLE SCRIPTS (npm runs these automatically on install — HIGH RISK):
{lifecycle}

SOURCE FILES ({n_files} files, {n_chars} chars{sample_note})
============
{files_block}
"""

FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "category": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "evidence": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["severity", "category", "file", "evidence", "explanation"],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["findings", "summary"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class AgentSpec:
    name: str
    focus_prompt: str


AGENTS: list[AgentSpec] = [
    AgentSpec(
        name="behavior",
        focus_prompt=(
            "Analyze the SOURCE CODE for malicious runtime behavior. Look for:\n"
            "- Data exfiltration (reading env vars, ssh keys, .npmrc, wallets, browser history) and sending them out\n"
            "- Backdoors / reverse shells / command-and-control beacons\n"
            "- Crypto miners (CPU-bound loops, mining pool connections)\n"
            "- Dropper behavior (downloading and executing remote code)\n"
            "- File system writes outside the package directory\n"
            "- Use of eval / Function / new Function on dynamic strings\n"
            "- child_process / spawn / exec calls\n"
            "- Outbound network calls (http, https, fetch, net.connect) to non-package hosts\n"
            "Ignore obfuscation alone (separate agent), naming (separate agent), and maintainer issues (separate agent)."
        ),
    ),
    AgentSpec(
        name="install_scripts",
        focus_prompt=(
            "Focus EXCLUSIVELY on the lifecycle scripts (preinstall, install, postinstall, etc.) shown in the context.\n"
            "These run automatically when a victim runs `npm install` — the #1 supply chain attack vector.\n"
            "Flag ANY non-trivial behavior here: downloads, execs, writes outside ./, env reads, network calls.\n"
            "A legitimate install script usually does: native build (node-gyp), simple file copy, or nothing.\n"
            "If lifecycle scripts are empty or trivial, return no findings with a one-line summary."
        ),
    ),
    AgentSpec(
        name="obfuscation",
        focus_prompt=(
            "Detect code OBFUSCATION used to hide intent. Look for:\n"
            "- Hex/unicode-escaped string blobs (\\x.., \\u..) that decode to readable strings\n"
            "- Base64 payloads passed to atob / Buffer.from / eval\n"
            "- Variable names like _0x... (javascript-obfuscator signature)\n"
            "- String arrays + rotation/decoder functions\n"
            "- Excessive minification on what claims to be a small utility\n"
            "- Heavy use of bracket notation to hide member access (window['atob'])\n"
            "Distinguish from legitimate minified bundles (large libraries often ship minified — that alone is not suspicious).\n"
            "Severity should be 'high' or 'critical' only when obfuscation hides behavior, not when it's pure minification."
        ),
    ),
    AgentSpec(
        name="maintainer",
        focus_prompt=(
            "Analyze MAINTAINER and PUBLISHER signals from the metadata in the context.\n"
            "Look for:\n"
            "- Mismatch between the package's listed maintainers and the publisher of THIS version (account takeover signal)\n"
            "- Single-character or random-looking maintainer usernames (throwaway account signal)\n"
            "- Author/maintainer pattern that doesn't match a real person/org\n"
            "- A very recent publish date combined with above signals\n"
            "Do NOT flag well-known maintainers. Source code is OUT of your scope — other agents handle that.\n"
            "If nothing stands out, return an empty findings list with a brief summary noting the publisher."
        ),
    ),
    AgentSpec(
        name="typosquat",
        focus_prompt=(
            "Check the PACKAGE NAME for typosquatting against well-known npm packages.\n"
            "Examples of squat patterns: 'reqeust' (request), 'lodahs' (lodash), 'discord.js-builders' (@discordjs/builders),\n"
            "'crossenv' (cross-env), 'cross-env.js' (cross-env), 'noblox.js-server' (noblox.js).\n"
            "Also flag: scoped/unscoped impersonation (e.g. unscoped 'babel-core' vs scoped @babel/core),\n"
            "homoglyph attacks (cyrillic letters in name), 'js' suffix on common names, plural/singular swaps.\n"
            "Provide the suspected impersonation target in the evidence field.\n"
            "If the name matches no popular package and shows no squat pattern, return empty findings."
        ),
    ),
]


def _format_files_block(bundle: PackageBundle) -> str:
    if not bundle.files:
        return "(no source files extracted)"
    parts = []
    for path, content in bundle.files.items():
        parts.append(f"--- FILE: {path} ---\n{content}")
    return "\n\n".join(parts)


def _format_lifecycle(bundle: PackageBundle) -> str:
    scripts = bundle.lifecycle_scripts
    if not scripts:
        return "(none)"
    return "\n".join(f"  {k}: {v}" for k, v in scripts.items())


def _format_maintainers(bundle: PackageBundle) -> str:
    if not bundle.maintainers:
        return "(none listed)"
    return ", ".join(
        f"{m.get('name', '?')} <{m.get('email', '?')}>"
        for m in bundle.maintainers
    )


def _format_publisher(bundle: PackageBundle) -> str:
    if not bundle.publisher:
        return "(unknown)"
    return f"{bundle.publisher.get('name', '?')} <{bundle.publisher.get('email', '?')}>"


def _build_system(bundle: PackageBundle) -> list[dict]:
    files_block = _format_files_block(bundle)
    text = SYSTEM_TEMPLATE.format(
        name=bundle.name,
        version=bundle.version,
        previous=bundle.previous_version or "(unknown)",
        published_at=bundle.published_at or "(unknown)",
        description=bundle.description or "(none)",
        author=bundle.author or "(none)",
        maintainers=_format_maintainers(bundle),
        publisher=_format_publisher(bundle),
        total_size=bundle.total_size_bytes,
        dependencies=", ".join(bundle.dependencies.keys()) or "(none)",
        lifecycle=_format_lifecycle(bundle),
        n_files=len(bundle.files),
        n_chars=sum(len(c) for c in bundle.files.values()),
        sample_note=f"; {bundle.sample_note}" if bundle.sample_note else "",
        files_block=files_block,
    )
    return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]


async def run_agent(
    client: anthropic.AsyncAnthropic, bundle: PackageBundle, spec: AgentSpec
) -> dict:
    response = await client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=_build_system(bundle),
        thinking={"type": "adaptive"},
        output_config={
            "effort": "high",
            "format": {"type": "json_schema", "schema": FINDINGS_SCHEMA},
        },
        messages=[{"role": "user", "content": spec.focus_prompt}],
    )

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        parsed = json.loads(text)
        findings = parsed.get("findings", [])
        summary = parsed.get("summary", "")
    except json.JSONDecodeError:
        findings = []
        summary = ""

    return {
        "name": spec.name,
        "findings": findings,
        "summary": summary,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_creation_input_tokens": getattr(
                response.usage, "cache_creation_input_tokens", 0
            ),
            "cache_read_input_tokens": getattr(
                response.usage, "cache_read_input_tokens", 0
            ),
        },
    }


async def run_all_agents(bundle: PackageBundle) -> list[dict]:
    async with anthropic.AsyncAnthropic() as client:
        return await asyncio.gather(
            *(run_agent(client, bundle, spec) for spec in AGENTS)
        )
