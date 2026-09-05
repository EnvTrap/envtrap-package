// test/fixtures/subprocess-leak.js
const { spawn } = require('node:child_process');

const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');
const child = spawn(process.execPath, ['-e', 'console.log("CHILD_ENV_RESULT:", process.env.TEST_SECRET_KEY)'], {
  env: { ...process.env, TEST_SECRET_KEY: secret }
});

child.stdout.on('data', (d) => process.stdout.write(d));
child.stderr.on('data', (d) => process.stderr.write(d));
