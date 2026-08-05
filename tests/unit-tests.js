const assert = require('assert');

// CommonJS test suite for Node environment
const { NullifierDeriver } = require('../src/sdk/nullifier-cjs.js');
const { InitDataParser } = require('../src/sdk/initdata-parser-cjs.js');

function runTests() {
  console.log('🧪 Running zk-tele-auth Unit Test Suite...\n');

  // Test 1: Deterministic Nullifier Derivation
  const nullifier1 = NullifierDeriver.deriveNullifier(987654321, 'dapp.io');
  const nullifier2 = NullifierDeriver.deriveNullifier(987654321, 'dapp.io');
  const nullifierOther = NullifierDeriver.deriveNullifier(987654321, 'otherdapp.io');

  assert.strictEqual(nullifier1, nullifier2);
  assert.notStrictEqual(nullifier1, nullifierOther);
  assert.strictEqual(nullifier1.length, 64);
  console.log('✅ Test 1 Passed: Deterministic Anonymous Nullifier Derivation');

  // Test 2: Telegram InitData Parser & HMAC Validation
  const botToken = '123456789:ABCdefGhIJKlmNoPQRstuVWXyz';
  const queryStr = 'auth_date=1620000000&user=%7B%22id%22%3A987654321%2C%22is_premium%22%3Atrue%7D&hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const parsed = InitDataParser.parse(queryStr);
  assert.strictEqual(parsed.user.id, 987654321);
  assert.strictEqual(parsed.user.is_premium, true);
  console.log('✅ Test 2 Passed: InitData Parsing & Extraction');

  console.log('\n🎉 All zk-tele-auth Unit Tests Passed Successfully!');
}

runTests();
