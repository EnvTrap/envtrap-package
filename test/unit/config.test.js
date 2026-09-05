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

// ============================================================================
// ConfigLoader Tests
// ============================================================================
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ConfigLoader, loadConfig } = require('../../dist/config/ConfigLoader.js');

test('ConfigLoader - returns defaults when envtrap.json is absent', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envtrap-config-test-'));
  try {
    const res = loadConfig(tmpDir);
    assert.strictEqual(res.loaded, false);
    assert.strictEqual(res.errors.length, 0);
    assert.deepStrictEqual(res.config, DEFAULT_CONFIG);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ConfigLoader - handles invalid JSON syntax gracefully', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envtrap-config-test-'));
  try {
    fs.writeFileSync(path.join(tmpDir, 'envtrap.json'), '{ invalid json syntax');
    const res = new ConfigLoader().load(tmpDir);
    assert.strictEqual(res.loaded, true);
    assert.strictEqual(res.errors.length, 1);
    assert.match(res.errors[0].message, /Failed to parse JSON/);
    assert.deepStrictEqual(res.config, DEFAULT_CONFIG);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ConfigLoader - loads, merges and validates valid custom config', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envtrap-config-test-'));
  try {
    const custom = {
      channels: { stdout: 'block', network: 'off' },
      exclusions: { domains: ['api.github.com'] },
      quiet: true
    };
    fs.writeFileSync(path.join(tmpDir, 'envtrap.json'), JSON.stringify(custom));
    const res = loadConfig(tmpDir);
    assert.strictEqual(res.loaded, true);
    assert.strictEqual(res.errors.length, 0);
    assert.strictEqual(res.config.channels.stdout, 'block');
    assert.strictEqual(res.config.channels.network, 'off');
    assert.strictEqual(res.config.exclusions.domains[0], 'api.github.com');
    assert.strictEqual(res.config.quiet, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ConfigValidator - non-object root and scalar errors', () => {
  const validator = new ConfigValidator();

  // Non-object root
  const rootErr1 = validator.validate(null);
  assert.strictEqual(rootErr1[0].message, 'Root config must be a JSON object');
  const rootErr2 = validator.validate('not an object');
  assert.strictEqual(rootErr2[0].message, 'Root config must be a JSON object');
  const rootErr3 = validator.validate([1, 2, 3]);
  assert.strictEqual(rootErr3[0].message, 'Root config must be a JSON object');

  // Non-object subsections
  const subErrors = validator.validate({
    channels: 'invalid',
    exclusions: 'invalid',
    entropy: 'invalid',
    logFile: 12345
  });
  assert.ok(subErrors.some(e => e.path === '$.channels'));
  assert.ok(subErrors.some(e => e.path === '$.exclusions'));
  assert.ok(subErrors.some(e => e.path === '$.entropy'));
  assert.ok(subErrors.some(e => e.path === '$.logFile'));

  // Unknown channel key
  const unknownKeyErr = validator.validate({
    channels: { unknown_channel: 'block' }
  });
  assert.ok(unknownKeyErr.some(e => e.message.includes('Unknown channel key')));
});

