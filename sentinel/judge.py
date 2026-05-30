"""Judge agent: merges the five analyst findings into a final verdict."""
from __future__ import annotations

import json

import anthropic

MODEL = "claude-opus-4-7"
MAX_TOKENS = 4000

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["clean", "suspicious", "malicious"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "headline": {"type": "string"},
        "reasoning": {"type": "string"},
        "top_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "evidence": {"type": "string"},
                    "flagged_by": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["severity", "category", "file", "evidence", "flagged_by"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["verdict", "confidence", "headline", "reasoning", "top_findings"],
    "additionalProperties": False,
}

JUDGE_SYSTEM = """You are the verdict judge for a supply-chain attack detection system.

Five specialized analyst agents (behavior, install_scripts, obfuscation, maintainer, typosquat)
have analyzed an npm package. You see all of their findings. Your job:

1. Pick a final verdict:
   - "malicious" — clear active attack (data exfil, backdoor, miner, dropper) or install-script malware
   - "suspicious" — meaningful red flags but ambiguous; warrants human review before install
   - "clean" — no real concerns, package looks legitimate

2. Pick confidence: low / medium / high

3. Write a one-line headline (what this package IS, in one sentence)

4. Write a short reasoning paragraph explaining the verdict using the analysts' evidence.

5. Surface the top findings (highest-severity, most specific evidence). Cross-reference which
   analysts agreed on the same issue (put their names in `flagged_by`). Merge duplicates.

Rules:
- Critical + high severity findings in behavior or install_scripts → almost always "malicious"
- Multiple medium findings across multiple analysts → at least "suspicious"
- Only obfuscation/minification with no behavioral findings → "clean" or "suspicious" (lean clean if it's a well-known minified library)
- Maintainer concerns alone → "suspicious" at most, never "malicious"
- A typosquat name alone is "suspicious"; combined with behavior findings → "malicious"
- Do not invent findings. Only synthesize what the analysts reported.
"""


async def run_judge(agent_results: list[dict]) -> dict:
    payload = {
        "agents": [
            {
                "name": r["name"],
                "summary": r.get("summary", ""),
                "findings": r["findings"],
            }
            for r in agent_results
        ]
    }
    user_msg = (
        "Here are the analyst reports as JSON. Synthesize the final verdict.\n\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```"
    )

    async with anthropic.AsyncAnthropic() as client:
        response = await client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=JUDGE_SYSTEM,
            thinking={"type": "adaptive"},
            output_config={
                "effort": "high",
                "format": {"type": "json_schema", "schema": VERDICT_SCHEMA},
            },
            messages=[{"role": "user", "content": user_msg}],
        )

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        verdict = json.loads(text)
    except json.JSONDecodeError:
        verdict = {
            "verdict": "suspicious",
            "confidence": "low",
            "headline": "judge output unparseable",
            "reasoning": "Judge response did not return valid JSON.",
            "top_findings": [],
        }

    verdict["_usage"] = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
    }
    return verdict
