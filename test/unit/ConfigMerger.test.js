// test/unit/ConfigMerger.test.js
const test = require('node:test');
const assert = require('node:assert');
const { ConfigMerger } = require('../../dist/config/ConfigMerger.js');
const { DEFAULT_CONFIG } = require('../../dist/config/ConfigTypes.js');

test('ConfigMerger - basic merge defaults', () => {
  const merger = new ConfigMerger();

  // Null input returns defaults
  const mergedNull = merger.merge(null);
  assert.deepStrictEqual(mergedNull, DEFAULT_CONFIG);

  // Partial update overrides defaults correctly
  const user = {
    channels: {
      stdout: 'block', // override warn -> block
      dns: 'off'       // override block -> off
    },
    entropy: {
      minLength: 24    // override 12 -> 24
    }
  };

  const merged = merger.merge(user);

  assert.strictEqual(merged.channels.stdout, 'block');
  assert.strictEqual(merged.channels.dns, 'off');
  assert.strictEqual(merged.channels.stderr, DEFAULT_CONFIG.channels.stderr); // unchanged
  assert.strictEqual(merged.entropy.minLength, 24);
  assert.strictEqual(merged.entropy.threshold, DEFAULT_CONFIG.entropy.threshold); // unchanged
});
