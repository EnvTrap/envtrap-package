// test/fixtures/subprocess-esm-leak.mjs
import { spawn } from 'node:child_process';

// Spawning via ESM import without passing options or env
const child = spawn(process.execPath, ['-e', 'console.log("ESM_CHILD_INHERITED:", process.env.TEST_SECRET_KEY)']);

child.stdout.on('data', (d) => process.stdout.write(d));
child.stderr.on('data', (d) => process.stderr.write(d));
