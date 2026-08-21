import assert from 'node:assert/strict';
import { validateDeploymentProfile } from '../scripts/lib/deployment-profile.mjs';

const commit = 'a'.repeat(40);
const complete = {
  schemaVersion: 1,
  status: 'approved',
  network: 'testnet',
  requiredCircuits: ['telegram_auth', 'priva_purchase_auth'],
  enableExperimentalPriva: true,
  independentReviewRequired: true,
  reviewedCommit: commit,
  applicationDomain: 'launchpad.zk-tele-auth.io',
  appDomainHash: '123',
  issuerKeyHash: '456',
  maxTokenAgeSec: 3600,
  requirePremium: true,
  maxAuthorizationTtlSec: 600,
  launchpadAddress: 'EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c',
  launchId: 'launch-1',
  launchIdHash: '789',
  pricePerUnitNano: '1000000000',
  perIdentityCap: '2',
  inventory: '100',
  acceptedAsset: 'native-ton',
  refundPolicy: 'accounted-credit-pending-reviewed-withdrawal-adapter',
  operatorApprovalReference: 'operator-review-1',
  mainnetApprovalReference: '',
};

const valid = validateDeploymentProfile(complete, { candidateCommit: commit, requirePriva: true });
assert.deepEqual(valid, { missing: [], invalid: [] });

const stale = validateDeploymentProfile({ ...complete, reviewedCommit: 'b'.repeat(40) }, { candidateCommit: commit, requirePriva: true });
assert.ok(stale.invalid.some((message) => message.includes('reviewedCommit does not match')));

const malformed = validateDeploymentProfile({ ...complete, appDomainHash: 'not-a-field', launchpadAddress: 'not-an-address' }, { candidateCommit: commit, requirePriva: true });
assert.ok(malformed.invalid.some((message) => message.includes('appDomainHash')));
assert.ok(malformed.invalid.some((message) => message.includes('launchpadAddress')));

const incomplete = validateDeploymentProfile({ ...complete, status: 'operator-input-required', inventory: 0 }, { candidateCommit: commit, requirePriva: true });
assert.ok(incomplete.missing.includes('status'));
assert.ok(incomplete.missing.includes('inventory'));

const generic = validateDeploymentProfile({
  ...complete,
  enableExperimentalPriva: false,
  independentReviewRequired: false,
  maxAuthorizationTtlSec: 0,
  launchpadAddress: '',
  launchId: '',
  launchIdHash: '',
  pricePerUnitNano: 0,
  perIdentityCap: 0,
  inventory: 0,
  acceptedAsset: '',
  refundPolicy: '',
}, { candidateCommit: commit, requirePriva: false });
assert.deepEqual(generic, { missing: [], invalid: [] });

console.log('deployment profile validation tests: passed');
process.exit(0);
