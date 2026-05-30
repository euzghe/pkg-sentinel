# Examples

Two synthetic fixtures for demonstrating pkg-sentinel without depending on
which malicious packages happen to still be live on the npm registry
(npm purges them shortly after disclosure).

## `synthetic-malicious/`

A fake package mimicking a typical credential-exfil supply chain attack:
postinstall hook reads `~/.ssh`, `~/.npmrc`, `~/.aws/credentials`, packs them,
and POSTs to a hardcoded remote host. Also includes a mildly obfuscated
helper to demonstrate the obfuscation analyst.

The file does **not actually execute** when scanned — pkg-sentinel only reads
sources statically.

```bash
sentinel scan-local examples/synthetic-malicious
```

Expected verdict: **malicious** (high confidence).

## `clean-utility/`

A trivially benign string utility — to verify the system does not produce
false positives on simple, legitimate packages.

```bash
sentinel scan-local examples/clean-utility
```

Expected verdict: **clean**.

## Scanning real packages

```bash
sentinel scan lodash@4.17.21
sentinel scan @babel/core
sentinel scan some-package@1.2.3 --exit-on suspicious
```
