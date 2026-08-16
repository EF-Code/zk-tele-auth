#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { runTolkCompiler } from '@ton/tolk-js';

const root = process.cwd();
const launchpadPath = path.join(root, 'contracts', 'priva_purchase_launchpad.tolk');
const reviewPath = path.join(root, 'docs', 'production', 'priva-launchpad-review.json');
if (!fs.existsSync(launchpadPath)) {
  console.error('BLOCKED: contracts/priva_purchase_launchpad.tolk is absent; the cryptographic verifier wrapper is not a purchase launchpad');
  process.exit(3);
}
const source = fs.readFileSync(launchpadPath, 'utf8');
for (const marker of [
  'PrivaPurchaseAuthVerifier.create',
  'verifyProof',
  'usedActionNullifiers',
  'usedQueryIds',
  'identityTotals',
  'recipient',
  'pricePerUnit',
  'totalRaised',
  'refundCredits',
  'reserveLaunchpadStorage',
  'no asynchronous settlement',
]) {
  if (!source.includes(marker)) {
    console.error(`ERROR: launchpad source does not expose required ${marker} handling`);
    process.exit(1);
  }
}
const compilation = await runTolkCompiler({
  entrypointFileName: path.relative(root, launchpadPath),
  fsReadCallback: (requestedPath) => fs.readFileSync(path.resolve(root, requestedPath), 'utf8'),
});
if (compilation.status === 'error') {
  console.error(`ERROR: launchpad does not compile: ${compilation.message}`);
  process.exit(1);
}
if (!fs.existsSync(reviewPath)) {
  console.error('BLOCKED: docs/production/priva-launchpad-review.json is absent');
  process.exit(3);
}
const review = JSON.parse(fs.readFileSync(reviewPath, 'utf8'));
const sourceCommit = (await import('node:child_process')).execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
if (review.schemaVersion !== 1 || review.status !== 'approved' || review.findingsClosed !== true || review.commit !== sourceCommit || String(review.codeHash || '').toLowerCase() !== String(compilation.codeHashHex || '').toLowerCase() || !review.reviewer || !review.reviewReference || !review.invariants || Object.keys(review.invariants).length < 6) {
  console.error('BLOCKED: Priva launchpad review is not approved with findings closed');
  if (review.status === 'approved' && review.findingsClosed === true) process.exit(1);
  process.exit(3);
}
console.log('✓ Priva launchpad composition source and review record are present');
