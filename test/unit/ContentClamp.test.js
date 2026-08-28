// test/unit/ContentClamp.test.js
const test = require('node:test');
const assert = require('node:assert');
const { ContentClamp } = require('../../dist/domain/ContentClamp.js');

test('ContentClamp - slice and clamp size limit', () => {
  const clamp = new ContentClamp(10); // 10 bytes clamp limit for testing

  const shortText = 'abc';
  assert.strictEqual(clamp.clamp(shortText), 'abc');

  const longText = 'abcdefghijklmnop';
  assert.strictEqual(clamp.clamp(longText), 'abcdefghij');

  const emptyText = '';
  assert.strictEqual(clamp.clamp(emptyText), '');
});
