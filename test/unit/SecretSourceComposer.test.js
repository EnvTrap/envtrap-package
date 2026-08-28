// test/unit/SecretSourceComposer.test.js
const test = require('node:test');
const assert = require('node:assert');
const { SecretSourceComposer } = require('../../dist/secrets/SecretSourceComposer.js');

test('SecretSourceComposer - composition and deduplication', () => {
  const sourceA = {
    load: () => [
      { name: 'STRIPE_SECRET_KEY', value: 'sk_test_12345678901234567890', source: 'env' },
      { name: 'GITHUB_TOKEN', value: 'ghp_abcdef1234567890abcdef123456', source: 'env' }
    ]
  };

  const sourceB = {
    load: () => [
      // Name collision, same value: should be deduplicated
      { name: 'STRIPE_SECRET_KEY', value: 'sk_test_12345678901234567890', source: 'dotenv' },
      // Name collision, different value: primary (sourceA) must win, sourceB discarded
      { name: 'GITHUB_TOKEN', value: 'ghp_different_value_999999999999', source: 'dotenv' },
      // Unique secret in B
      { name: 'NEW_KEY', value: 'some_new_unique_secret_value_123', source: 'dotenv' }
    ]
  };

  const composer = new SecretSourceComposer([sourceA, sourceB]);
  const secrets = composer.load();

  assert.strictEqual(secrets.length, 3);

  const stripe = secrets.find(s => s.name === 'STRIPE_SECRET_KEY');
  const github = secrets.find(s => s.name === 'GITHUB_TOKEN');
  const newKey = secrets.find(s => s.name === 'NEW_KEY');

  assert.notStrictEqual(stripe, undefined);
  assert.notStrictEqual(github, undefined);
  assert.notStrictEqual(newKey, undefined);

  // Validate values (primary wins)
  assert.strictEqual(stripe.value, 'sk_test_12345678901234567890');
  assert.strictEqual(github.value, 'ghp_abcdef1234567890abcdef123456');
  assert.strictEqual(newKey.value, 'some_new_unique_secret_value_123');
});
