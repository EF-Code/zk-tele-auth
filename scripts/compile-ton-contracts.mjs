#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Cell } from '@ton/core';
import { runTolkCompiler, getTolkCompilerVersion } from '@ton/tolk-js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requested = process.argv.slice(2).filter((value) => value !== '--json');
const names = requested.length ? requested : ['generic-verifier', 'priva-verifier', 'priva-launchpad'];
const entrypoints = {
  'generic-verifier': 'contracts/zk_tele_auth_verifier.tolk',
  'priva-verifier': 'contracts/priva_purchase_auth_verifier_wrapper.tolk',
  'priva-launchpad': 'contracts/priva_purchase_launchpad.tolk',
};
const output = [];
for (const name of names) {
  const entrypointFileName = entrypoints[name];
  if (!entrypointFileName) throw new Error(`unknown TON contract: ${name}`);
  const result = await runTolkCompiler({
    entrypointFileName,
    fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
  });
  if (result.status === 'error') throw new Error(`${name}: ${result.message}`);
  const code = Cell.fromBoc(Buffer.from(result.codeBoc64, 'base64'))[0];
  output.push({ name, entrypointFileName, compiler: await getTolkCompilerVersion(), codeHash: code.hash().toString('hex'), codeBoc64: result.codeBoc64 });
}
console.log(JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), contracts: output }, null, 2));
