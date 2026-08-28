// test/unit/SecretMatcher.test.js
const test = require('node:test');
const assert = require('node:assert');
const { SecretMatcher } = require('../../dist/domain/SecretMatcher.js');
const { looksLikeSecret } = require('../../dist/detection/fingerprint.js');

test('looksLikeSecret validation', () => {
  // Short values should be rejected regardless of entropy
  assert.strictEqual(looksLikeSecret('abc'), false);
  assert.strictEqual(looksLikeSecret('sk_test_123'), false); // too short (11 chars)

  // Standard Stripe test key matches pattern and satisfies min length
  assert.strictEqual(looksLikeSecret('sk_test_51NzABCDEFGHIJ123456789012'), true);

  // AWS Access Key ID matches pattern
  assert.strictEqual(looksLikeSecret('AKIAIOSFODNN7EXAMPLE'), true);

  // GitHub token matches pattern
  assert.strictEqual(looksLikeSecret('ghp_123456789012345678901234567890123456'), true);

  // Generic bearer token
  assert.strictEqual(looksLikeSecret('Bearer 1234567890123456789012345'), true);

  // High entropy value (random uuid/hash style keys) should match
  assert.strictEqual(looksLikeSecret('f13a7b9c2d8e4f5a6b0c1d2e3f4a5b6c'), true);

  // Low entropy value (like standard repetitive sequence) should be rejected
  assert.strictEqual(looksLikeSecret('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), false);
});

test('SecretMatcher - active secret matching', () => {
  const secret = { name: 'DB_PASSWORD', value: 'my-super-secret-key-123', source: 'env' };
  const matcher = new SecretMatcher([secret], { minLength: 12, threshold: 3.5 });

  // Exact match
  const matches = matcher.findIn('connection string: my-super-secret-key-123 to database');
  assert.strictEqual(matches.length, 1);
  assert.strictEqual(matches[0].name, 'DB_PASSWORD');

  // Non-matching query
  const noMatches = matcher.findIn('other harmless text');
  assert.strictEqual(noMatches.length, 0);
});
