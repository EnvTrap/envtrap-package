// test/e2e/cli.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { runCli } = require('./harness.js');

const CLEAN_APP = path.resolve(__dirname, '../fixtures/clean-app.js');

test('CLI: --version returns valid semver', async () => {
  const { code, stdout } = await runCli(['--version']);
  assert.strictEqual(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('CLI: --help displays command options and channels', async () => {
  const { code, stdout } = await runCli(['--help']);
  assert.strictEqual(code, 0);
  assert.match(stdout, /Usage: envtrap/);
  assert.match(stdout, /Commands:/);
  assert.match(stdout, /run/);
  assert.match(stdout, /check/);
});

test('CLI: check command succeeds when no envtrap.json is found', async () => {
  const { code, stdout } = await runCli(['check'], {}, path.resolve(__dirname, '../fixtures'));
  assert.strictEqual(code, 0);
  assert.match(stdout, /No envtrap\.json found\. Using default settings\./);
});

test('CLI: executes clean application with zero exit code', async () => {
  const { code, stdout, stderr } = await runCli(['run', '--no-mitm', 'node', CLEAN_APP]);
  assert.strictEqual(code, 0);
  assert.match(stdout, /Clean application running smoothly\./);
  assert.doesNotMatch(stderr, /SECRET LEAK DETECTED/);
});

test('CLI: --quiet suppresses banner and alerts', async () => {
  const { code, stdout, stderr } = await runCli(['run', '--quiet', '--no-mitm', 'node', CLEAN_APP]);
  assert.strictEqual(code, 0);
  assert.doesNotMatch(stderr, /\[envtrap\] warning: Active channels/);
  assert.match(stdout, /Clean application running smoothly\./);
});
