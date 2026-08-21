import { Address } from '@ton/core';

const UINT32_MAX = 0xffff_ffff;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const MAX_INVENTORY = 1_000_000n;
const BASE_REQUIRED = [
  'network', 'reviewedCommit', 'applicationDomain', 'appDomainHash', 'issuerKeyHash',
  'maxTokenAgeSec', 'operatorApprovalReference',
];

function isPlaceholder(value) {
  return value === undefined || value === null || value === '' || value === 0 || String(value) === '0' || String(value).includes('PENDING');
}

function canonicalUnsigned(value, name, maximum, errors, missing) {
  if (isPlaceholder(value)) {
    missing.push(name);
    return null;
  }
  const raw = typeof value === 'number' ? (Number.isSafeInteger(value) ? String(value) : '') : String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) {
    errors.push(`${name} must be a canonical decimal integer`);
    return null;
  }
  const parsed = BigInt(raw);
  if (parsed <= 0n || parsed > maximum) errors.push(`${name} must be in 1..${maximum.toString()}`);
  return parsed;
}

function boundedUint32(value, name, errors, missing) {
  const parsed = canonicalUnsigned(value, name, BigInt(UINT32_MAX), errors, missing);
  return parsed === null ? null : Number(parsed);
}

function validateAddress(value, errors, missing) {
  if (isPlaceholder(value)) {
    missing.push('launchpadAddress');
    return;
  }
  try {
    const address = Address.parse(String(value));
    if (address.workChain !== 0) errors.push('launchpadAddress must be a basechain address');
  } catch {
    errors.push('launchpadAddress is not a valid TON address');
  }
}

/**
 * Validate operator-controlled deployment data without inventing defaults.
 * `missing` means the operator has not supplied evidence yet; `invalid` means
 * supplied data is malformed or does not describe the exact candidate commit.
 */
export function validateDeploymentProfile(profile, { candidateCommit, requirePriva = true } = {}) {
  const missing = [];
  const invalid = [];
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return { missing: [], invalid: ['profile must be a JSON object'] };
  if (profile.schemaVersion !== 1) invalid.push('schemaVersion must be 1');
  if (typeof profile.enableExperimentalPriva !== 'boolean') invalid.push('enableExperimentalPriva must be boolean');
  if (typeof profile.independentReviewRequired !== 'boolean') invalid.push('independentReviewRequired must be boolean');
  if (profile.independentReviewRequired === false && profile.network === 'mainnet') invalid.push('independentReviewRequired must be true for mainnet');
  if (profile.independentReviewRequired === false && profile.enableExperimentalPriva === true) invalid.push('independentReviewRequired must be true when Priva is enabled');
  if (profile.status !== 'approved') missing.push('status');
  if (isPlaceholder(profile.network)) missing.push('network');
  else if (!['testnet', 'mainnet'].includes(profile.network)) invalid.push('network must be testnet or mainnet');
  for (const key of BASE_REQUIRED.slice(1)) if (isPlaceholder(profile[key])) missing.push(key);
  if (!Array.isArray(profile.requiredCircuits) || profile.requiredCircuits.length === 0 || profile.requiredCircuits.some((name) => typeof name !== 'string' || !name)) {
    invalid.push('requiredCircuits must contain circuit names');
  }
  if (Array.isArray(profile.requiredCircuits) && !profile.requiredCircuits.includes('telegram_auth')) invalid.push('requiredCircuits must include telegram_auth');
  if (!isPlaceholder(profile.reviewedCommit) && !/^[0-9a-f]{40}$/i.test(String(profile.reviewedCommit))) invalid.push('reviewedCommit must be a full 40-character Git commit');
  if (candidateCommit && !isPlaceholder(profile.reviewedCommit) && String(profile.reviewedCommit).toLowerCase() !== String(candidateCommit).toLowerCase()) invalid.push('reviewedCommit does not match the candidate HEAD');
  for (const key of ['appDomainHash', 'issuerKeyHash']) canonicalUnsigned(profile[key], key, UINT256_MAX, invalid, missing);
  boundedUint32(profile.maxTokenAgeSec, 'maxTokenAgeSec', invalid, missing);
  if (typeof profile.requirePremium !== 'boolean') invalid.push('requirePremium must be boolean');
  if (isPlaceholder(profile.applicationDomain)) missing.push('applicationDomain');
  else if (/[^\x20-\x7e]/.test(String(profile.applicationDomain))) invalid.push('applicationDomain contains non-printable characters');
  if (isPlaceholder(profile.operatorApprovalReference)) missing.push('operatorApprovalReference');
  if (profile.network === 'mainnet' && isPlaceholder(profile.mainnetApprovalReference)) missing.push('mainnetApprovalReference');
  const privaRequired = requirePriva || profile.enableExperimentalPriva === true;
  if (privaRequired) {
    if (Array.isArray(profile.requiredCircuits) && !profile.requiredCircuits.includes('priva_purchase_auth')) invalid.push('requiredCircuits must include priva_purchase_auth when Priva is enabled');
    boundedUint32(profile.maxAuthorizationTtlSec, 'maxAuthorizationTtlSec', invalid, missing);
    if (profile.acceptedAsset !== 'native-ton') invalid.push('acceptedAsset must be native-ton');
    if (profile.refundPolicy !== 'accounted-credit-pending-reviewed-withdrawal-adapter') invalid.push('refundPolicy must name the reviewed withdrawal-adapter policy');
    validateAddress(profile.launchpadAddress, invalid, missing);
    if (isPlaceholder(profile.launchId)) missing.push('launchId');
    canonicalUnsigned(profile.launchIdHash, 'launchIdHash', UINT256_MAX, invalid, missing);
    canonicalUnsigned(profile.pricePerUnitNano, 'pricePerUnitNano', UINT64_MAX, invalid, missing);
    canonicalUnsigned(profile.perIdentityCap, 'perIdentityCap', MAX_INVENTORY, invalid, missing);
    canonicalUnsigned(profile.inventory, 'inventory', MAX_INVENTORY, invalid, missing);
  }
  return { missing: [...new Set(missing)], invalid: [...new Set(invalid)] };
}
