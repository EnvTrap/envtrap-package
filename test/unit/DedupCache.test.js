// test/unit/DedupCache.test.js
const test = require('node:test');
const assert = require('node:assert');
const { DedupCache } = require('../../dist/domain/DedupCache.js');

test('DedupCache - deduplication & TTL logic', async () => {
  const cache = new DedupCache(50); // Use 50ms TTL for testing

  // First time seeing the key: not a duplicate
  assert.strictEqual(cache.isDuplicate('STRIPE_KEY'), false);

  // Record seeing the key
  cache.record('STRIPE_KEY');

  // Second time seeing the key immediately: duplicate
  assert.strictEqual(cache.isDuplicate('STRIPE_KEY'), true);

  // Wait for TTL (50ms) to expire
  await new Promise(resolve => setTimeout(resolve, 60));

  // Should now be recognized as a new event (not a duplicate)
  assert.strictEqual(cache.isDuplicate('STRIPE_KEY'), false);
});
