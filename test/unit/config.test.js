// test/unit/config.test.js
const test = require('node:test');
const assert = require('node:assert');
const { ConfigValidator } = require('../../dist/config/ConfigValidator.js');
const { ConfigMerger } = require('../../dist/config/ConfigMerger.js');
const { isPathExcluded } = require('../../dist/config/PathMatcher.js');
const { DEFAULT_CONFIG } = require('../../dist/config/ConfigTypes.js');

// ============================================================================
// ConfigValidator Tests
// ============================================================================
test('ConfigValidator - valid configurations', () => {
  const validator = new ConfigValidator();
  const errors = validator.validate(DEFAULT_CONFIG);
  assert.strictEqual(errors.length, 0);
});

test('ConfigValidator - invalid configurations', () => {
  const validator = new ConfigValidator();

  const badConfig = {
    channels: {
      stdout: 'allow', // invalid mode
      stderr: 'warn'
    },
    exclusions: {
      domains: 'api.stripe.com', // must be array
      paths: ['src/**/*.ts']
    },
    entropy: {
      threshold: 'high' // must be number
    },
    quiet: 'yes' // must be boolean
  };

  const errors = validator.validate(badConfig);
  assert.strictEqual(errors.length > 0, true);

  assert.notStrictEqual(errors.find(e => e.path === '$.channels.stdout'), undefined);
  assert.notStrictEqual(errors.find(e => e.path === '$.exclusions.domains'), undefined);
  assert.notStrictEqual(errors.find(e => e.path === '$.entropy.threshold'), undefined);
  assert.notStrictEqual(errors.find(e => e.path === '$.quiet'), undefined);
});

// ============================================================================
// ConfigMerger Tests
// ============================================================================
test('ConfigMerger - configurations merge', () => {
  const merger = new ConfigMerger();

  // Null falls back to defaults
  assert.deepStrictEqual(merger.merge(null), DEFAULT_CONFIG);

  const user = {
    channels: {
      stdout: 'block',
      network: 'off'
    },
    exclusions: {
      domains: ['api.openai.com']
    },
    entropy: {
      minLength: 16
    },
    quiet: true
  };

  const merged = merger.merge(user);

  assert.strictEqual(merged.channels.stdout, 'block');
  assert.strictEqual(merged.channels.network, 'off');
  assert.strictEqual(merged.channels.dns, DEFAULT_CONFIG.channels.dns); // unchanged
  assert.strictEqual(merged.exclusions.domains[0], 'api.openai.com');
  assert.strictEqual(merged.entropy.minLength, 16);
  assert.strictEqual(merged.quiet, true);
});

// ============================================================================
// PathMatcher Tests
// ============================================================================
test('PathMatcher - glob rules', () => {
  const patterns = ['test/**', '**/__tests__/**', 'src/lib/secret.ts'];

  // Exact relative path
  assert.strictEqual(isPathExcluded('src/lib/secret.ts', patterns), true);
  assert.strictEqual(isPathExcluded('src\\lib\\secret.ts', patterns), true); // handle backslashes

  // Wildcard match
  assert.strictEqual(isPathExcluded('test/app.test.js', patterns), true);

  // Recursive double glob match
  assert.strictEqual(isPathExcluded('src/domain/__tests__/logic.js', patterns), true);

  // Rejects normal files
  assert.strictEqual(isPathExcluded('src/domain/scanner.ts', patterns), false);
});
