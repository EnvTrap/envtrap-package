// test/unit/secrets.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { EnvSecretSource } = require('../../dist/secrets/EnvSecretSource.js');
const { DotEnvSecretSource } = require('../../dist/secrets/DotEnvSecretSource.js');
const { SecretSourceComposer } = require('../../dist/secrets/SecretSourceComposer.js');

const ENTROPY_CFG = { minLength: 12, threshold: 3.5 };
const TEMP_DOTENV = path.join(__dirname, '.env.temp');

// ============================================================================
// EnvSecretSource Tests
// ============================================================================
test('EnvSecretSource - load environment secrets', () => {
  // Inject a mock secret that looks like a secret into process.env
  process.env.MOCK_STRIPE_KEY = 'sk_test_' + '51NzABCDEFGHIJ123456789012';
  
  const source = new EnvSecretSource(ENTROPY_CFG);
  const secrets = source.load();
  
  const found = secrets.find(s => s.name === 'MOCK_STRIPE_KEY');
  assert.notStrictEqual(found, undefined);
  assert.strictEqual(found.value, 'sk_test_' + '51NzABCDEFGHIJ123456789012');
  
  // Clean up env
  delete process.env.MOCK_STRIPE_KEY;
});

// ============================================================================
// DotEnvSecretSource Tests
// ============================================================================
test('DotEnvSecretSource - load file secrets', () => {
  // Write temporary .env file
  fs.writeFileSync(TEMP_DOTENV, 'SECRET_KEY_VAR=' + 'sk_test_' + '51NzABCDEFGHIJ123456789012\nBLOCKED_VAR=short\n');

  try {
    const source = new DotEnvSecretSource(TEMP_DOTENV, ENTROPY_CFG);
    const secrets = source.load();

    const found = secrets.find(s => s.name === 'SECRET_KEY_VAR');
    assert.notStrictEqual(found, undefined);
    assert.strictEqual(found.value, 'sk_test_' + '51NzABCDEFGHIJ123456789012');

    // The short value must be excluded in the loading phase by looksLikeSecret gate
    const blocked = secrets.find(s => s.name === 'BLOCKED_VAR');
    assert.strictEqual(blocked, undefined);
  } finally {
    if (fs.existsSync(TEMP_DOTENV)) {
      fs.unlinkSync(TEMP_DOTENV);
    }
  }
});

// ============================================================================
// SecretSourceComposer Tests
// ============================================================================
test('SecretSourceComposer - resolution rules', () => {
  const sourceA = {
    load: () => [
      { name: 'API_KEY', value: 'sk_test_' + '51NzABCDEFGHIJ123456789012', source: 'env' }
    ]
  };

  const sourceB = {
    load: () => [
      // Duplicate key and value (should deduplicate)
      { name: 'API_KEY', value: 'sk_test_' + '51NzABCDEFGHIJ123456789012', source: 'dotenv' },
      // Duplicate key, different value (primary sourceA wins)
      { name: 'API_KEY', value: 'sk_test_' + 'different_val_9999999999', source: 'dotenv' },
      // Unique key
      { name: 'NEW_KEY', value: 'sk_test_' + 'another_valid_key_555555', source: 'dotenv' }
    ]
  };

  const composer = new SecretSourceComposer([sourceA, sourceB]);
  const secrets = composer.load();

  assert.strictEqual(secrets.length, 2);
  
  const api = secrets.find(s => s.name === 'API_KEY');
  const unique = secrets.find(s => s.name === 'NEW_KEY');
  
  assert.strictEqual(api.value, 'sk_test_' + '51NzABCDEFGHIJ123456789012');
  assert.strictEqual(unique.value, 'sk_test_' + 'another_valid_key_555555');
});
