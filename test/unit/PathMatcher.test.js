// test/unit/PathMatcher.test.js
const test = require('node:test');
const assert = require('node:assert');
const { isPathExcluded } = require('../../dist/config/PathMatcher.js');

test('isPathExcluded - glob path exclusions', () => {
  const patterns = ['test/**', '**/__tests__/**', 'src/lib/secret.ts'];

  // Match exact path
  assert.strictEqual(isPathExcluded('src/lib/secret.ts', patterns), true);
  assert.strictEqual(isPathExcluded('src\\lib\\secret.ts', patterns), true); // handle backslashes

  // Match wildcard pattern
  assert.strictEqual(isPathExcluded('test/unit/app.js', patterns), true);

  // Match double glob anywhere in path
  assert.strictEqual(isPathExcluded('src/__tests__/scanner.js', patterns), true);
  assert.strictEqual(isPathExcluded('src/domain/__tests__/logic.js', patterns), true);

  // Rejects non-matching paths
  assert.strictEqual(isPathExcluded('src/domain/scanner.ts', patterns), false);
  assert.strictEqual(isPathExcluded('package.json', patterns), false);
});
