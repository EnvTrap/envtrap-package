// test/unit/domain.test.js
const test = require('node:test');
const assert = require('node:assert');
const { SecretMatcher } = require('../../dist/domain/SecretMatcher.js');
const { looksLikeSecret } = require('../../dist/detection/fingerprint.js');
const { DedupCache } = require('../../dist/domain/DedupCache.js');
const { OutputRedactor } = require('../../dist/domain/OutputRedactor.js');
const { ContentClamp } = require('../../dist/domain/ContentClamp.js');
const { getSha256 } = require('../../dist/detection/fingerprint.js');

const ENTROPY_CFG = { minLength: 12, threshold: 3.5 };

// ============================================================================
// SecretMatcher & looksLikeSecret Tests
// ============================================================================
test('SecretMatcher - looksLikeSecret regex patterns', () => {
  // Stripe Keys
  assert.strictEqual(looksLikeSecret('sk_live_' + '51NzABCDEFGHIJ123456789012'), true);
  assert.strictEqual(looksLikeSecret('sk_test_' + '51NzABCDEFGHIJ123456789012'), true);

  // AWS Access Key ID
  assert.strictEqual(looksLikeSecret('AKIA' + 'IOSFODNN7EXAMPLE'), true);

  // GitHub Personal Access Token
  assert.strictEqual(looksLikeSecret('ghp_' + 'abcdef1234567890abcdef12345678901234'), true);

  // Generic Bearer Token
  assert.strictEqual(looksLikeSecret('Bearer ' + 'abcdef1234567890abcdef12'), true);

  // Slack Bot Token
  assert.strictEqual(looksLikeSecret('xoxb-' + '1234567890-' + 'abcdef1234567890abcdef12'), true);

  // SendGrid API Key
  assert.strictEqual(looksLikeSecret('SG.' + 'abcdef1234567890abcdef' + '.' + '1234567890abcdef1234567890abcdef1234567890a'), true);
});

test('SecretMatcher - looksLikeSecret length validation', () => {
  // Too short - rejected regardless of pattern
  assert.strictEqual(looksLikeSecret('sk_test_123', 12, 3.5), false);
  assert.strictEqual(looksLikeSecret('AKIA123', 12, 3.5), false);
});

test('SecretMatcher - looksLikeSecret entropy threshold', () => {
  // Random high-entropy strings should be matched as secret candidates
  assert.strictEqual(looksLikeSecret('z8k2m9q5x4w7p3v1n6t0', 12, 3.0), true);

  // Repetitive low-entropy strings should be rejected
  assert.strictEqual(looksLikeSecret('aaaaaaaaaaaaaaaaaaaa', 12, 3.5), false);
});

test('SecretMatcher - findIn operations', () => {
  const secret1 = { name: 'S1', value: 'sk_test_' + '51NzABCDEFGHIJ123456789012', source: 'env' };
  const secret2 = { name: 'S2', value: 'AKIA' + 'IOSFODNN7EXAMPLE', source: 'env' };
  
  const matcher = new SecretMatcher([secret1, secret2], ENTROPY_CFG);

  // Find single matches
  const matches1 = matcher.findIn('text containing sk_test_' + '51NzABCDEFGHIJ123456789012 key');
  assert.strictEqual(matches1.length, 1);
  assert.strictEqual(matches1[0].name, 'S1');

  // Find multiple matches in same block
  const matches2 = matcher.findIn('keys: sk_test_' + '51NzABCDEFGHIJ123456789012 and AKIA' + 'IOSFODNN7EXAMPLE');
  assert.strictEqual(matches2.length, 2);

  // Ignore invalid secret values (e.g. if the secret doesn't satisfy looksLikeSecret check)
  const invalidSecret = { name: 'S3', value: 'short', source: 'env' };
  const matcher2 = new SecretMatcher([invalidSecret], ENTROPY_CFG);
  assert.strictEqual(matcher2.findIn('text containing short key').length, 0);
});

test('SecretMatcher - detects encoded secrets (Base64, Hex, URL-encoded, JSON-escaped) (Issue #5)', () => {
  const secret = { name: 'API_TOKEN', value: 'SuperSecretToken12345!', source: 'env' };
  const matcher = new SecretMatcher([secret], ENTROPY_CFG);

  // Verbatim
  assert.strictEqual(matcher.findIn('payload: SuperSecretToken12345!').length, 1);

  // Standard Base64
  const b64 = Buffer.from('SuperSecretToken12345!').toString('base64');
  const b64Matches = matcher.findIn(`Authorization: Basic ${b64}`);
  assert.strictEqual(b64Matches.length, 1);
  assert.strictEqual(b64Matches[0].name, 'API_TOKEN');

  // Hex encoded
  const hex = Buffer.from('SuperSecretToken12345!').toString('hex');
  const hexMatches = matcher.findIn(`data: ${hex}`);
  assert.strictEqual(hexMatches.length, 1);
  assert.strictEqual(hexMatches[0].name, 'API_TOKEN');

  // URL encoded
  const urlEnc = encodeURIComponent('SuperSecretToken12345!');
  const urlMatches = matcher.findIn(`https://example.com/api?token=${urlEnc}`);
  assert.strictEqual(urlMatches.length, 1);
  assert.strictEqual(urlMatches[0].name, 'API_TOKEN');

  // JSON escaped secret
  const secretWithSpecial = { name: 'SPECIAL_SECRET', value: 'secret"with\\special\nchars', source: 'env' };
  const matcherSpecial = new SecretMatcher([secretWithSpecial], { minLength: 6, threshold: 2.0 });
  const jsonEscaped = JSON.stringify('secret"with\\special\nchars').slice(1, -1);
  const jsonMatches = matcherSpecial.findIn(`{"data":"${jsonEscaped}"}`);
  assert.strictEqual(jsonMatches.length, 1);
  assert.strictEqual(jsonMatches[0].name, 'SPECIAL_SECRET');
});

test('SecretMatcher - findMatchingKeys environment mapping', () => {
  const secret1 = { name: 'DB_PASS', value: 'pass123456789', source: 'env' };
  const secret2 = { name: 'API_KEY', value: 'key1234567890', source: 'env' };
  const matcher = new SecretMatcher([secret1, secret2], ENTROPY_CFG);

  const env = { DB_PASS: 'pass123456789', OTHER_VAR: 'hello' };
  const matches = matcher.findMatchingKeys(env);

  assert.strictEqual(matches.length, 1);
  assert.strictEqual(matches[0].name, 'DB_PASS');
});

// ============================================================================
// DedupCache Tests
// ============================================================================
test('DedupCache - duplication logic', async () => {
  const cache = new DedupCache(30);

  // First check
  assert.strictEqual(cache.isDuplicate('KEY_A'), false);
  cache.record('KEY_A');

  // Immediate check is a duplicate
  assert.strictEqual(cache.isDuplicate('KEY_A'), true);

  // Different key is not a duplicate
  assert.strictEqual(cache.isDuplicate('KEY_B'), false);

  // Wait for TTL expiration
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.strictEqual(cache.isDuplicate('KEY_A'), false);
});

// ============================================================================
// OutputRedactor Tests
// ============================================================================
test('OutputRedactor - redaction scenarios', () => {
  const secret = { name: 'MY_KEY', value: 'secret123456789', source: 'env' };
  const redactor = new OutputRedactor([secret]);

  const raw = 'The secret value is secret123456789 inside text.';
  const hash = getSha256(secret.value).slice(0, 8);
  const expected = `The secret value is [REDACTED: SHA256:${hash}] inside text.`;

  assert.strictEqual(redactor.redact(raw), expected);
});

// ============================================================================
// ContentClamp Tests
// ============================================================================
test('ContentClamp - size boundary clamping', () => {
  const clamp = new ContentClamp(5);

  assert.strictEqual(clamp.clamp('abcdefgh'), 'abcde');
  assert.strictEqual(clamp.clamp('abc'), 'abc');
  assert.strictEqual(clamp.clamp(''), '');
});
