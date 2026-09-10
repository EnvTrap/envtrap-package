// test/fixtures/subprocess-args-leak.js
const { spawn } = require('node:child_process');

const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');
const child = spawn(process.execPath, ['-e', `console.log("Passed arg: ${secret}")`], {
  env: {} // Clean env, secret passed in CLI args
});

child.stdout.on('data', (d) => process.stdout.write(d));
child.stderr.on('data', (d) => process.stderr.write(d));
