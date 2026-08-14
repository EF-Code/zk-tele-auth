#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const launchpadPath = path.join(root, 'contracts', 'priva_purchase_launchpad.tolk');
const reviewPath = path.join(root, 'docs', 'production', 'priva-launchpad-review.json');
if (!fs.existsSync(launchpadPath)) {
  console.error('BLOCKED: contracts/priva_purchase_launchpad.tolk is absent; the cryptographic verifier wrapper is not a purchase launchpad');
  process.exit(1);
}
if (!fs.existsSync(reviewPath)) {
  console.error('BLOCKED: docs/production/priva-launchpad-review.json is absent');
  process.exit(1);
}
const source = fs.readFileSync(launchpadPath, 'utf8');
for (const marker of ['actionNullifier', 'identityNullifier', 'recipient', 'refund', 'bounce']) {
  if (!source.includes(marker)) {
    console.error(`BLOCKED: launchpad source does not expose reviewed ${marker} handling`);
    process.exit(1);
  }
}
const review = JSON.parse(fs.readFileSync(reviewPath, 'utf8'));
if (review.status !== 'approved' || review.findingsClosed !== true) {
  console.error('BLOCKED: Priva launchpad review is not approved with findings closed');
  process.exit(1);
}
console.log('✓ Priva launchpad composition source and review record are present');

