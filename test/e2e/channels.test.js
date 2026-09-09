// test/e2e/channels.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { runCli } = require('./harness.js');

const STDOUT_APP = path.resolve(__dirname, '../fixtures/stdout-leak.js');
const STDERR_APP = path.resolve(__dirname, '../fixtures/stderr-leak.js');
const SUBPROCESS_APP = path.resolve(__dirname, '../fixtures/subprocess-leak.js');
const SUBPROCESS_DEFAULT_ENV_APP = path.resolve(__dirname, '../fixtures/subprocess-default-env.js');
const SUBPROCESS_ESM_APP = path.resolve(__dirname, '../fixtures/subprocess-esm-leak.mjs');
const DNS_APP = path.resolve(__dirname, '../fixtures/dns-leak.js');

const FAKE_SECRET = ['sk', 'live', 'verysecretpayload1234567890'].join('_');

test('Channel STDOUT: redacts secret and reports leak without exposing plaintext', async () => {
  const { stdout, stderr } = await runCli(
    ['run', '--no-mitm', 'node', STDOUT_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  // Plaintext secret should NEVER appear in stdout or stderr
  assert.strictEqual(stdout.includes(FAKE_SECRET), false);
  assert.strictEqual(stderr.includes(FAKE_SECRET), false);

  // Output must be redacted with SHA256 digest
  assert.match(stdout, /\[REDACTED: SHA256:[a-f0-9]+\]/);

  // Stderr must alert on STDOUT channel leak
  assert.match(stderr, /SECRET LEAK DETECTED/);
  assert.match(stderr, /Channel:\s+STDOUT/);
  assert.match(stderr, /TEST_SECRET_KEY/);
});

test('Channel STDERR: redacts secret and reports leak on stderr', async () => {
  const { stderr } = await runCli(
    ['run', '--no-mitm', 'node', STDERR_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  // Plaintext secret should NEVER appear
  assert.strictEqual(stderr.includes(FAKE_SECRET), false);

  // Redacted text and alert should appear
  assert.match(stderr, /\[REDACTED: SHA256:[a-f0-9]+\]/);
  assert.match(stderr, /SECRET LEAK DETECTED/);
  assert.match(stderr, /Channel:\s+STDERR/);
});

test('Channel CHILD PROCESS: alerts on subprocess spawn attempting to inherit secrets', async () => {
  const { stderr } = await runCli(
    ['run', '--no-mitm', 'node', SUBPROCESS_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  // Alert on child process channel
  assert.match(stderr, /SECRET LEAK DETECTED/);
  assert.match(stderr, /Channel:\s+CHILD PROC/);
  assert.match(stderr, /TEST_SECRET_KEY/);
});

test('Channel CHILD PROCESS: alerts on subprocess spawn with omitted options.env (default inheritance)', async () => {
  const { stderr } = await runCli(
    ['run', '--no-mitm', 'node', SUBPROCESS_DEFAULT_ENV_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  // Alert on child process channel when options.env is omitted
  assert.match(stderr, /SECRET LEAK DETECTED/);
  assert.match(stderr, /Channel:\s+CHILD PROC/);
  assert.match(stderr, /TEST_SECRET_KEY/);
});

const SUBPROCESS_EXECFILE_APP = path.resolve(__dirname, '../fixtures/subprocess-execfile.js');

test('Channel CHILD PROCESS: alerts on ESM subprocess spawn with omitted options.env', async () => {
  const { stderr } = await runCli(
    ['run', '--no-mitm', 'node', SUBPROCESS_ESM_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  // Alert on child process channel from ESM spawn
  assert.match(stderr, /SECRET LEAK DETECTED/);
  assert.match(stderr, /Channel:\s+CHILD PROC/);
  assert.match(stderr, /TEST_SECRET_KEY/);
});

test('Channel CHILD PROCESS: execFile preserves callbacks and options objects', async () => {
  const { stdout } = await runCli(
    ['run', '--no-mitm', 'node', SUBPROCESS_EXECFILE_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  assert.match(stdout, /RESULT1:ARG_CB_OK/);
  assert.match(stdout, /RESULT2:OPT_CB_OK:HELLO/);
});

test('Channel DNS: intercepts and blocks domain query containing secret', async () => {
  const { stdout, stderr } = await runCli(
    ['run', '--no-mitm', 'node', DNS_APP],
    { TEST_SECRET_KEY: FAKE_SECRET }
  );

  // Plaintext secret must not appear
  assert.strictEqual(stderr.includes(FAKE_SECRET), false);

  // Alert on DNS channel
  assert.match(stderr, /SECRET LEAK DETECTED/);
  assert.match(stderr, /Channel:\s+DNS/);

  // Verification that DNS lookup was blocked
  assert.ok(
    /DNS_BLOCKED_RESULT:|DNS_THROWN_RESULT:/.test(stdout) || /Channel:\s+DNS/.test(stderr),
    'Expected DNS lookup to be intercepted or blocked'
  );
});
