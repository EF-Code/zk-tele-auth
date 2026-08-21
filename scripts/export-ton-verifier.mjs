#!/usr/bin/env node
/**
 * Regenerate the embedded Telegram verifier constants from the checked-in
 * verification key without replacing the policy, replay, or accounting code
 * surrounding ZkTeleAuthVerifier.create().
 *
 * The default mode updates the contract. Pass --check in CI to fail when the
 * constants are stale instead of writing anything.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateVerifier } from 'export-ton-verifier';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = path.join(root, 'contracts', 'zk_tele_auth_verifier.tolk');
const vkeyPath = path.join(root, 'artifacts', 'telegram_auth', 'telegram_auth_vkey.json');
const checkOnly = process.argv.includes('--check');
const createFunction = /fun ZkTeleAuthVerifier\.create\(\): ZkTeleAuthVerifier \{[\s\S]*?\n\}/;

const temporaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zk-tele-auth-ton-export-'));
const generatedPath = path.join(temporaryDir, 'generated.tolk');

try {
  if (!fs.existsSync(vkeyPath)) throw new Error('telegram_auth verification key is missing');
  if (!fs.existsSync(contractPath)) throw new Error('Telegram TON verifier contract is missing');
  await generateVerifier(vkeyPath, generatedPath, {
    lang: 'tolk',
    contractName: 'ZkTeleAuthVerifier',
    quiet: true,
  });
  const current = fs.readFileSync(contractPath, 'utf8');
  const generated = fs.readFileSync(generatedPath, 'utf8');
  const generatedMatch = generated.match(createFunction);
  if (!generatedMatch) throw new Error('generated verifier create function not found');
  const replacement = generatedMatch[0].replace(/\r/g, '');
  if (!createFunction.test(current)) throw new Error('checked-in verifier create function not found');
  const updated = current.replace(createFunction, replacement);
  if (updated === current) {
    console.log(checkOnly ? '✓ TON verifier constants match telegram_auth_vkey.json' : 'TON verifier constants are already current');
  } else if (checkOnly) {
    throw new Error('TON verifier constants are stale relative to telegram_auth_vkey.json');
  } else {
    fs.writeFileSync(contractPath, updated);
    console.log('updated ZkTeleAuthVerifier.create() constants from telegram_auth_vkey.json');
  }
} finally {
  fs.rmSync(temporaryDir, { recursive: true, force: true });
}
