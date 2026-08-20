#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';

const templates = ['compose.dev.yaml', 'compose.production.example.yaml'];
for (const file of templates) {
  const text = fs.readFileSync(file, 'utf8');
  assert.match(text, /^services:/m, `${file} must define services`);
  assert.match(text, /read_only:\s*true/, `${file} must use a read-only filesystem`);
  assert.match(text, /cap_drop:\s*\[ALL\]/, `${file} must drop Linux capabilities`);
  assert.match(text, /no-new-privileges:true/, `${file} must enable no-new-privileges`);
  assert.doesNotMatch(text, /github_pat_|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY/, `${file} contains secret-like material`);
}
const production = fs.readFileSync('compose.production.example.yaml', 'utf8');
assert.match(production, /external:\s*true/);
assert.match(production, /TELEGRAM_BOT_TOKEN_REF/);
assert.match(production, /ZK_TELE_AUTH_ISSUER_SECRET_REF/);
console.log('deployment template checks: passed');
