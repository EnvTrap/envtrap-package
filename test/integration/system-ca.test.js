// test/integration/system-ca.test.js
const test = require('node:test');
const assert = require('node:assert');
const { injectSystemCA, removeSystemCA } = require('../../dist/mitm/SystemCaTrust.js');
const { CertificateAuthority } = require('../../dist/mitm/CertificateAuthority.js');

test('SystemCaTrust - gracefully handles non-root execution without throwing', () => {
  const ca = new CertificateAuthority();
  const { certPath } = ca.initCA();

  // Non-root call should not throw
  assert.doesNotThrow(() => {
    injectSystemCA(certPath, true);
  });

  assert.doesNotThrow(() => {
    removeSystemCA(certPath);
  });
});
