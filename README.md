# pkg-sentinel

Multi-agent supply chain attack scanner for npm packages, powered by Claude.

When you run `npm install`, the package and **all of its transitive dependencies** —
often hundreds of them — execute on your machine. If any maintainer's account is
compromised or any new version smuggles in malicious code, your laptop, your CI
runner, or your production servers become the attacker's. This has happened to
[event-stream](https://github.com/dominictarr/event-stream/issues/116) (Bitcoin
wallets), [ua-parser-js](https://github.com/advisories/GHSA-pjwm-rvh2-c87w)
(crypto miner), [xz-utils](https://en.wikipedia.org/wiki/XZ_Utils_backdoor)
(SSH backdoor), and is detected roughly **200 times per week** on npm alone.

`pkg-sentinel` is a swarm of five specialized Claude agents that read a package
version's source code and metadata and decide whether it is `clean`,
`suspicious`, or `malicious` — with reasoning you can audit.

## How it works

```
                        ┌──────────────────────────┐
                        │  npm registry / local    │
                        │  package fetcher         │
                        └──────────┬───────────────┘
                                   │  PackageBundle
                                   ▼
                ┌──────────────────────────────────────┐
                │  shared system prompt (cached)       │
                │  metadata + lifecycle + source files │
                └──────────────────────────────────────┘
                                   │
       ┌──────────┬────────────────┼────────────────┬──────────────┐
       ▼          ▼                ▼                ▼              ▼
   behavior  install_scripts  obfuscation     maintainer       typosquat
       │          │                │                │              │
       └──────────┴────────────────┼────────────────┴──────────────┘
                                   ▼
                          ┌──────────────────┐
                          │  judge agent     │
                          │  → verdict       │
                          └──────────────────┘
```

- **behavior** — looks for data exfil, backdoors, miners, droppers, `eval`, `child_process`
- **install_scripts** — focuses on `preinstall` / `postinstall` (the #1 attack vector)
- **obfuscation** — detects hex-encoded payloads, `_0x...` names, base64 droppers
- **maintainer** — flags publisher/maintainer mismatch (account takeover signal)
- **typosquat** — checks the name against known popular package patterns
- **judge** — synthesizes the five reports into a final verdict + confidence

All five analysts share one cached system prompt containing the package context,
so the first agent pays the cache-write premium and the rest read at ~10% cost.

## Install

```bash
git clone https://github.com/euzghe/pkg-sentinel.git
cd pkg-sentinel
python3 -m venv .venv
.venv/bin/pip install -e .
```

Set your Anthropic API key:

```bash
cp .env.example .env
# edit .env, paste your key
```

## Use

Scan a live npm package:

```bash
sentinel scan lodash@4.17.21
sentinel scan @babel/core
sentinel scan some-suspicious-pkg --exit-on suspicious   # for CI
sentinel scan lodash --json                              # machine-readable
```

Scan a local package directory (e.g. before publishing your own):

```bash
sentinel scan-local ./my-package
sentinel scan-local examples/synthetic-malicious   # demo: known-bad
sentinel scan-local examples/clean-utility         # demo: known-good
```

## Verify without an API key

Use `--dry-run` to fetch + build the agent prompts without calling the LLM:

```bash
sentinel scan-local examples/synthetic-malicious --dry-run
sentinel scan lodash@4.17.21 --dry-run
```

This shows what would be sent to each agent, the prompt sizes, and the
expected token cost — useful for verifying the pipeline before paying anything.

## Example output (illustrative)

```
╔══════════════════════════════════════════════════════════════════╗
║  pkg-sentinel scan: dev-stats-helper@1.0.4                       ║
╚══════════════════════════════════════════════════════════════════╝

Verdict:    MALICIOUS (confidence: high)
Headline:   Postinstall payload exfiltrates SSH keys + cloud credentials

Reasoning
  The postinstall hook executes scripts/setup.js, which reads ~/.ssh/id_rsa,
  ~/.npmrc, ~/.aws/credentials, base64-encodes them with the process
  environment, and POSTs to a hex-obfuscated endpoint. Three analysts
  (behavior, install_scripts, obfuscation) independently flagged the same
  payload. No legitimate "developer statistics" tool needs SSH keys.

Top findings
  [CRITICAL] credential_exfiltration — scripts/setup.js
    evidence: fs.readFileSync on ~/.ssh/id_rsa, ~/.npmrc, ~/.aws/credentials
    flagged by: behavior, install_scripts
  [HIGH] obfuscated_c2_endpoint — scripts/setup.js
    evidence: hex-escaped string array _0x1a2b decodes to remote URL
    flagged by: obfuscation, behavior

Per-agent summary
  ! behavior — 3 finding(s)   Reads sensitive home-directory files and POSTs them.
  ! install_scripts — 1 finding(s)   postinstall executes the exfil payload.
  ! obfuscation — 1 finding(s)   Hex-encoded array hides C2 hostname.
  · maintainer — 0 finding(s)   Single publisher, no takeover signal.
  · typosquat — 0 finding(s)   Name is original, not a squat.
```

## Roadmap

- **v0.1 (this release)** — CLI scanner, 5 agents + judge, local + npm registry
- **v0.2** — On-chain verdict attestations via Ethereum Attestation Service (Base Sepolia, free)
  so verdicts are tamper-proof and consumable by other CI systems
- **v0.3** — Registry firehose listener: ingest every new npm publish in real time,
  publish attestations within seconds of release
- **v0.4** — `safe-install` CLI wrapper: checks attestations before `npm install` proceeds
- **v0.5** — Web dashboard + dependency-graph (Neo4j) navigation

## Why this matters

Today's defenses (Socket.dev, Snyk) are centralized, paid, and proprietary.
`pkg-sentinel` aims to be the opposite: open-source, multi-perspective by
construction, with verdicts anyone can read and verify on-chain. A collective
immune system for the JavaScript ecosystem.
