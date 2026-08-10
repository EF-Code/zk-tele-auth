import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateVerifier } from 'export-ton-verifier';
import { runTolkCompiler } from '@ton/tolk-js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = path.join(root, 'contracts', 'priva_purchase_auth_verifier.tolk');
const wrapperPath = path.join(root, 'contracts', 'priva_purchase_auth_verifier_wrapper.tolk');
const vkeyPath = path.join(root, 'artifacts', 'priva_purchase_auth', 'priva_purchase_auth_vkey.json');
const temporaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'priva-purchase-ton-check-'));
const generatedPath = path.join(temporaryDir, 'generated.tolk');

function extractVerifierConstants(source) {
  const match = source.match(/fun PrivaPurchaseAuthVerifier\.create\(\): PrivaPurchaseAuthVerifier \{[\s\S]*?\n\}/);
  if (!match) throw new Error('unable to locate PrivaPurchaseAuthVerifier.create() constants');
  return match[0].replace(/\r\n/g, '\n');
}

try {
  await generateVerifier(vkeyPath, generatedPath, {
    lang: 'tolk', contractName: 'PrivaPurchaseAuthVerifier', quiet: true,
  });
  const contractSource = fs.readFileSync(contractPath, 'utf8');
  const generatedSource = fs.readFileSync(generatedPath, 'utf8');
  if (extractVerifierConstants(contractSource) !== extractVerifierConstants(generatedSource)) {
    throw new Error('Priva purchase verifier constants are stale relative to priva_purchase_auth_vkey.json');
  }
  const compilation = await runTolkCompiler({
    entrypointFileName: path.relative(root, wrapperPath),
    fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
  });
  if (compilation.status === 'error') throw new Error(compilation.message);
  console.log(`  ✓ Priva purchase verifier key matches artifacts and Tolk compiles (${compilation.codeHashHex})`);
} finally {
  fs.rmSync(temporaryDir, { recursive: true, force: true });
}
