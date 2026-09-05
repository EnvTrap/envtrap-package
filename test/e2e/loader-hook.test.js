// test/e2e/loader-hook.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { runWithImport } = require('./harness.js');

const DNS_APP = path.resolve(__dirname, '../fixtures/dns-leak.js');
const STDOUT_APP = path.resolve(__dirname, '../fixtures/stdout-leak.js');
const CASES_APP = path.resolve(__dirname, '../fixtures/loader-hook-cases.js');

const SECRET_NAME = 'TEST_SECRET_KEY';
const SECRET_VALUE = ['sk', 'live', 'verysecretpayload1234567890'].join('_');

test('Loader Hook: blocks DNS query when loaded directly via node --import', async () => {
  const env = {
    TEST_SECRET_KEY: SECRET_VALUE,
    __ENVTRAP_SECRETS_MAP__: JSON.stringify({ [SECRET_NAME]: SECRET_VALUE }),
    __ENVTRAP_SECRET_NAMES__: JSON.stringify([SECRET_NAME]),
    __ENVTRAP_CONFIG_MODES__: JSON.stringify({ dns: 'block' })
  };

  const { stdout, stderr } = await runWithImport(DNS_APP, env);

  // Stderr hook emits [envtrap] DNS leak message
  assert.match(stderr, /\[envtrap\] DNS leak:/);
  assert.match(stderr, /TEST_SECRET_KEY/);

  // Resolution was intercepted/blocked
  assert.match(stdout, /DNS_BLOCKED_RESULT:|DNS_THROWN_RESULT:/);
});

test('Loader Hook: redacts stdout writes for excluded paths when configured', async () => {
  const env = {
    TEST_SECRET_KEY: SECRET_VALUE,
    __ENVTRAP_SECRETS_MAP__: JSON.stringify({ [SECRET_NAME]: SECRET_VALUE }),
    __ENVTRAP_SECRET_NAMES__: JSON.stringify([SECRET_NAME]),
    __ENVTRAP_PATH_EXCLUSIONS__: JSON.stringify(['**/stdout-leak.js'])
  };

  const { stdout } = await runWithImport(STDOUT_APP, env);

  // Pre-redacted by hooks.mjs for excluded path
  assert.strictEqual(stdout.includes(SECRET_VALUE), false);
  assert.match(stdout, /\[REDACTED: PATH_EXCLUDED\]/);
});

test('Loader Hook: blocks child_process when mode is block', async () => {
  const env = {
    TEST_SECRET_KEY: SECRET_VALUE,
    __ENVTRAP_SECRETS_MAP__: JSON.stringify({ [SECRET_NAME]: SECRET_VALUE }),
    __ENVTRAP_SECRET_NAMES__: JSON.stringify([SECRET_NAME]),
    __ENVTRAP_CONFIG_MODES__: JSON.stringify({ child_process: 'block', dns: 'block' })
  };

  const { stdout, stderr } = await runWithImport(CASES_APP, env);

  assert.match(stderr, /\[envtrap\] Child process leak: secret "TEST_SECRET_KEY"/);
  assert.match(stdout, /SPAWN_BLOCKED:/);
  assert.match(stdout, /EXEC_BLOCKED:/);
});

test('Loader Hook: warns on child_process without throwing when mode is warn', async () => {
  const env = {
    TEST_SECRET_KEY: SECRET_VALUE,
    __ENVTRAP_SECRETS_MAP__: JSON.stringify({ [SECRET_NAME]: SECRET_VALUE }),
    __ENVTRAP_SECRET_NAMES__: JSON.stringify([SECRET_NAME]),
    __ENVTRAP_CONFIG_MODES__: JSON.stringify({ child_process: 'warn', dns: 'warn' })
  };

  const { stdout, stderr } = await runWithImport(CASES_APP, env);

  // Stderr still receives warnings
  assert.match(stderr, /\[envtrap\] Child process leak: secret "TEST_SECRET_KEY"/);
  // But functions do NOT throw
  assert.doesNotMatch(stdout, /SPAWN_BLOCKED:/);
  assert.doesNotMatch(stdout, /EXEC_BLOCKED:/);
});
