// test/fixtures/grandchild-secrets-leak.js
const { spawn } = require('node:child_process');

const grandchild = spawn(process.execPath, [
  '-e',
  `console.log("Grandchild stdout: " + (process.env.TEST_SECRET_KEY || "no_secret"));`
], {
  env: { TEST_SECRET_KEY: process.env.TEST_SECRET_KEY }
});

grandchild.stdout.on('data', (d) => process.stdout.write(d));
grandchild.stderr.on('data', (d) => process.stderr.write(d));
