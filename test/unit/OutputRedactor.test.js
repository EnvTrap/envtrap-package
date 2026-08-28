// test/unit/OutputRedactor.test.js
const test = require('node:test');
const assert = require('node:assert');
const { OutputRedactor } = require('../../dist/domain/OutputRedactor.js');
const { getSha256 } = require('../../dist/detection/fingerprint.js');

test('OutputRedactor - redaction of secrets', () => {
  const secret1 = { name: 'KEY_ONE', value: 'secret-val-one-123456', source: 'env' };
  const secret2 = { name: 'KEY_TWO', value: 'secret-val-two-987654', source: 'env' };
  
  const redactor = new OutputRedactor([secret1, secret2]);
  
  const rawText = 'My keys are: secret-val-one-123456 and secret-val-two-987654.';
  const redactedText = redactor.redact(rawText);
  
  const hash1 = getSha256(secret1.value).slice(0, 8);
  const hash2 = getSha256(secret2.value).slice(0, 8);
  
  const expectedText = `My keys are: [REDACTED: SHA256:${hash1}] and [REDACTED: SHA256:${hash2}].`;
  
  assert.strictEqual(redactedText, expectedText);
});
