// test/fixtures/subprocess-default-env.js
const { spawn } = require('node:child_process');

// Spawning without passing options or options.env (relies on default process.env inheritance)
const child = spawn(process.execPath, ['-e', 'console.log("CHILD_INHERITED:", process.env.TEST_SECRET_KEY)']);

child.stdout.on('data', (d) => process.stdout.write(d));
child.stderr.on('data', (d) => process.stderr.write(d));
