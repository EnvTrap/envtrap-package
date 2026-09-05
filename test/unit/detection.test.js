// test/unit/detection.test.js
const test = require('node:test');
const assert = require('node:assert');
const {
  getSha256,
  shannonEntropy,
  looksLikeSecret,
  scanContent,
  extractContext
} = require('../../dist/detection/fingerprint.js');
const { DETERMINISTIC_PATTERNS } = require('../../dist/detection/patterns.js');

test('Detection - SHA-256 generation', () => {
  const hash = getSha256('hello-world');
  assert.strictEqual(typeof hash, 'string');
  assert.strictEqual(hash.length, 64);
  // Known SHA-256 for 'hello-world'
  assert.strictEqual(hash, 'afa27b44d43b02a9fea41d13cedc2e4016cfcf87c5dbf990e593669aa8ce286d');

  // Empty string SHA-256
  assert.strictEqual(
    getSha256(''),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
});

test('Detection - Shannon entropy math', () => {
  // Empty string
  assert.strictEqual(shannonEntropy(''), 0);
  // Homogeneous strings
  assert.strictEqual(shannonEntropy('AAAAAAAAAAAAAAA'), 0);
  assert.strictEqual(shannonEntropy('1111111111111111'), 0);
  // 2 characters alternating
  assert.ok(shannonEntropy('abababababab') <= 1.0);
  // 4 characters equal frequency -> log2(4) = 2.0
  assert.strictEqual(Math.round(shannonEntropy('abcdabcdabcd') * 100) / 100, 2.0);
  // High entropy random string
  assert.ok(shannonEntropy('a8b9c1d2e3f4g5h6i7j8k9l0') > 3.5);
  // Unicode / multilingual characters
  const unicodeEntropy = shannonEntropy('🔒🔑🛡️⚔️✨');
  assert.ok(unicodeEntropy > 0);
});

test('Detection - Deterministic regex pattern matching', () => {
  // 1. Stripe Live Key
  const stripeLive = ['sk', 'live', '1234567890abcdef12345678'].join('_');
  assert.strictEqual(looksLikeSecret(stripeLive), true);
  // 2. Stripe Test Key
  const stripeTest = ['sk', 'test', '1234567890abcdef12345678'].join('_');
  assert.strictEqual(looksLikeSecret(stripeTest), true);
  // 3. AWS Access Key ID
  assert.strictEqual(looksLikeSecret('AKIAIOSFODNN7EXAMPLE'), true);
  // 4. GitHub Personal Access Token
  assert.strictEqual(looksLikeSecret('ghp_' + 'A'.repeat(36)), true);
  // 5. SendGrid API Key
  const sendgridKey = ['SG', 'a'.repeat(22), 'b'.repeat(43)].join('.');
  assert.strictEqual(looksLikeSecret(sendgridKey), true);
  // 6. Slack Bot Token
  const slackToken = ['xoxb', '12345678901', '12345678901', 'abcdefghijklmnopqrstuvwx'].join('-');
  assert.strictEqual(looksLikeSecret(slackToken), true);
  // 7. Generic Bearer Token
  assert.strictEqual(looksLikeSecret('Bearer ' + 'c'.repeat(30)), true);

  // Negative tests for deterministic formats
  assert.strictEqual(looksLikeSecret('sk_fake_1234567890abcdef12345678', 12, 5.0), false);
  assert.strictEqual(looksLikeSecret('AKIA123', 5, 5.0), false); // Too short for AWS
  assert.strictEqual(looksLikeSecret('ghp_short_token', 12, 5.0), false); // Too short for PAT
  assert.strictEqual(looksLikeSecret('SG.invalid_length', 12, 5.0), false);
  assert.strictEqual(looksLikeSecret('xoxa-12345678901-12345678901-abcdefghijklmnopqrstuvwx', 12, 5.0), false);
});

test('Detection - Secret gate length and entropy thresholds', () => {
  // Below minLength gate
  assert.strictEqual(looksLikeSecret('short', 12, 3.5), false);
  assert.strictEqual(looksLikeSecret('12345678901', 12, 3.5), false); // length 11

  // Exactly minLength (12)
  assert.strictEqual(looksLikeSecret('foobarfoobar', 12, 3.5), false); // low entropy
  assert.strictEqual(looksLikeSecret('a8b9c1d2e3f4', 12, 3.5), true); // high entropy

  // Custom length and entropy parameters
  assert.strictEqual(looksLikeSecret('abcde', 5, 2.0), true);
  assert.strictEqual(looksLikeSecret('abcde', 5, 3.0), false);
  assert.strictEqual(looksLikeSecret('xK9#mQ2$vL5*pW8!', 12, 3.5), true);
});

test('Detection - scanContent identifies present secrets', () => {
  const stripeLive = ['sk', 'live', '1234567890abcdef12345678'].join('_');
  const secrets = [
    { name: 'STRIPE', value: stripeLive, source: 'env' },
    { name: 'AWS', value: 'AKIAIOSFODNN7EXAMPLE', source: 'env' },
    { name: 'LOW_ENTROPY', value: 'foobarfoobarfoobar', source: 'env' },
    { name: 'SPECIAL_CHARS', value: 's3cr3t$#.+*[special]', source: 'env' }
  ];

  // Matches single secret
  const p1 = `Sending request to Stripe with auth: ${stripeLive} now`;
  assert.deepStrictEqual(scanContent(p1, secrets), ['STRIPE']);

  // Matches multiple secrets in one payload
  const p2 = `Multiple: AKIAIOSFODNN7EXAMPLE and ${stripeLive}`;
  const m2 = scanContent(p2, secrets);
  assert.strictEqual(m2.includes('STRIPE'), true);
  assert.strictEqual(m2.includes('AWS'), true);

  // Secrets containing special characters are matched via plain substring search
  const p3 = 'Log: key is s3cr3t$#.+*[special] in system';
  assert.deepStrictEqual(scanContent(p3, secrets), ['SPECIAL_CHARS']);

  // Clean or empty contents
  assert.strictEqual(scanContent('clean text without keys', secrets).length, 0);
  assert.strictEqual(scanContent('', secrets).length, 0);
  assert.strictEqual(scanContent(p1, []).length, 0); // Empty secrets array
});

test('Detection - extractContext redacts matching secret with SHA256 digest', () => {
  const secret = ['sk', 'live', '1234567890abcdef12345678'].join('_');
  const expectedHash = getSha256(secret).slice(0, 8);

  // Secret in the middle
  const content = `prefix text https://api.stripe.com?key=${secret}&other=123 suffix text`;
  const snippet = extractContext(content, secret, 20);
  assert.strictEqual(snippet.includes(secret), false);
  assert.strictEqual(snippet.includes(`[REDACTED: SHA256:${expectedHash}]`), true);

  // Secret at index 0
  const headContent = `${secret} is at the very beginning`;
  const headSnippet = extractContext(headContent, secret, 10);
  assert.strictEqual(headSnippet.startsWith(`[REDACTED: SHA256:${expectedHash}]`), true);

  // Secret at end of string
  const tailContent = `Ending with ${secret}`;
  const tailSnippet = extractContext(tailContent, secret, 10);
  assert.strictEqual(tailSnippet.endsWith(`[REDACTED: SHA256:${expectedHash}]`), true);

  // Non-existent secret
  assert.strictEqual(extractContext(content, 'non_existent_secret'), '');
});
