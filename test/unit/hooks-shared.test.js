// test/unit/hooks-shared.test.js
const test = require('node:test');
const assert = require('node:assert');

test('Hooks Shared - isPathExcluded glob matching', async () => {
  const { isPathExcluded } = await import('../../dist/hooks/shared.mjs');

  const patterns = ['**/test/**', 'src/safe/*.ts', 'utils.js'];

  // Matching paths
  assert.strictEqual(isPathExcluded('/home/project/test/fixture.js', patterns), true);
  assert.strictEqual(isPathExcluded('/home/project/src/safe/logger.ts', patterns), true);
  assert.strictEqual(isPathExcluded('/home/project/utils.js', patterns), true);

  // Windows-style backslashes
  assert.strictEqual(isPathExcluded('C:\\project\\test\\fixture.js', patterns), true);

  // Non-matching paths
  assert.strictEqual(isPathExcluded('/home/project/src/danger/exfil.ts', patterns), false);
  assert.strictEqual(isPathExcluded('/home/project/index.js', patterns), false);
  assert.strictEqual(isPathExcluded('', patterns), false);
  assert.strictEqual(isPathExcluded(null, patterns), false);
  assert.strictEqual(isPathExcluded('/path/foo.js', []), false);
});

test('Hooks Shared - checkHighEntropyDns detects tunneling domains', async () => {
  const { checkHighEntropyDns } = await import('../../dist/hooks/shared.mjs');

  // Normal, low-entropy domains
  assert.strictEqual(checkHighEntropyDns('api.stripe.com', 3.5, 12), false);
  assert.strictEqual(checkHighEntropyDns('google.com', 3.5, 12), false);
  assert.strictEqual(checkHighEntropyDns('github.com', 3.5, 12), false);
  assert.strictEqual(checkHighEntropyDns('localhost', 3.5, 12), false);

  // High entropy sublabel (e.g. Base64 / Hex token chunk embedded in subdomain)
  // 'a8b9c1d2e3f4g5h6i7j8k9l0' has length 24 and entropy > 3.5
  assert.strictEqual(checkHighEntropyDns('a8b9c1d2e3f4g5h6i7j8k9l0.attacker.com', 3.5, 12), true);

  // Invalid or empty inputs
  assert.strictEqual(checkHighEntropyDns('', 3.5, 12), false);
  assert.strictEqual(checkHighEntropyDns(null, 3.5, 12), false);
});

test('Hooks Shared - preRedact masks secrets with PATH_EXCLUDED', async () => {
  const { preRedact } = await import('../../dist/hooks/shared.mjs');
  const fakeStripe = ['sk', 'live', '1234567890abcdef123456'].join('_');

  const secretsMap = {
    STRIPE_KEY: fakeStripe,
    AWS_KEY: 'AKIAIOSFODNN7EXAMPLE'
  };

  const text = `Log output with key: ${fakeStripe} and AWS: AKIAIOSFODNN7EXAMPLE`;
  const redacted = preRedact(text, secretsMap);

  assert.strictEqual(redacted.includes(fakeStripe), false);
  assert.strictEqual(redacted.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.match(redacted, /\[REDACTED: PATH_EXCLUDED\]/);

  // Text without secrets remains identical
  const clean = 'Clean log message';
  assert.strictEqual(preRedact(clean, secretsMap), clean);
});
