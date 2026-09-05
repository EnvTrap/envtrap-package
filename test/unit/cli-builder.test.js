// test/unit/cli-builder.test.js
const test = require('node:test');
const assert = require('node:assert');
const { ChildEnvBuilder } = require('../../dist/cli/ChildEnvBuilder.js');
const { HookMessageParser } = require('../../dist/cli/HookMessageParser.js');
const { DEFAULT_CONFIG } = require('../../dist/config/ConfigTypes.js');

test('ChildEnvBuilder - builds environment with MITM enabled', () => {
  const builder = new ChildEnvBuilder();
  const fakeStripe = ['sk', 'live', '1234567890abcdef123456'].join('_');
  const secrets = [
    { name: 'STRIPE_KEY', value: fakeStripe, source: 'env' }
  ];

  const env = builder.build({
    mitmEnabled: true,
    proxyPort: 8888,
    caCertPath: '/tmp/ca.pem',
    config: DEFAULT_CONFIG,
    secrets,
    hooksPath: '/path/to/hooks.mjs'
  });

  assert.strictEqual(env.HTTP_PROXY, 'http://127.0.0.1:8888');
  assert.strictEqual(env.HTTPS_PROXY, 'http://127.0.0.1:8888');
  assert.strictEqual(env.NODE_EXTRA_CA_CERTS, '/tmp/ca.pem');
  assert.match(env.NODE_OPTIONS, /--import \/path\/to\/hooks\.mjs/);
  assert.match(env.NO_PROXY, /localhost/);

  // Injected serialization metadata
  const secretsMap = JSON.parse(env.__ENVTRAP_SECRETS_MAP__);
  assert.strictEqual(secretsMap['STRIPE_KEY'], fakeStripe);

  const names = JSON.parse(env.__ENVTRAP_SECRET_NAMES__);
  assert.deepStrictEqual(names, ['STRIPE_KEY']);
});

test('ChildEnvBuilder - builds environment with MITM disabled', () => {
  const builder = new ChildEnvBuilder();
  const env = builder.build({
    mitmEnabled: false,
    proxyPort: 0,
    caCertPath: '',
    config: DEFAULT_CONFIG,
    secrets: [],
    hooksPath: '/path/to/hooks.mjs'
  });

  assert.strictEqual(env.HTTP_PROXY, undefined);
  assert.strictEqual(env.HTTPS_PROXY, undefined);
  assert.strictEqual(env.NODE_EXTRA_CA_CERTS, undefined);
  assert.match(env.NODE_OPTIONS, /--import \/path\/to\/hooks\.mjs/);
});

test('ChildEnvBuilder - preserves existing NODE_OPTIONS', () => {
  const oldNodeOptions = process.env.NODE_OPTIONS;
  try {
    process.env.NODE_OPTIONS = '--max-old-space-size=4096';
    const builder = new ChildEnvBuilder();
    const env = builder.build({
      mitmEnabled: false,
      proxyPort: 0,
      caCertPath: '',
      config: DEFAULT_CONFIG,
      secrets: [],
      hooksPath: '/path/to/hooks.mjs'
    });

    assert.strictEqual(env.NODE_OPTIONS, '--max-old-space-size=4096 --import /path/to/hooks.mjs');
  } finally {
    process.env.NODE_OPTIONS = oldNodeOptions;
  }
});

test('HookMessageParser - parses child process leak protocols', () => {
  const parser = new HookMessageParser();

  const msg = parser.parse('[envtrap] Child process leak: secret "MY_TOKEN" passed to: /bin/bash');
  assert.strictEqual(msg.type, 'child_process_leak');
  assert.strictEqual(msg.secretName, 'MY_TOKEN');
  assert.strictEqual(msg.detail, '/bin/bash');
});

test('HookMessageParser - parses DNS leak and warning protocols', () => {
  const parser = new HookMessageParser();

  const leak = parser.parse('[envtrap] DNS leak: secret "AWS_SECRET" found in lookup of: evil.attacker.com');
  assert.strictEqual(leak.type, 'dns_leak');
  assert.strictEqual(leak.secretName, 'AWS_SECRET');
  assert.strictEqual(leak.detail, 'evil.attacker.com');

  const warning = parser.parse('[envtrap] DNS warning: high-entropy lookup detected: a8b9c1d2e3f4g5.test.com');
  assert.strictEqual(warning.type, 'dns_warning');
  assert.strictEqual(warning.detail, 'a8b9c1d2e3f4g5.test.com');

  assert.strictEqual(parser.parse('random normal line output').type, 'none');
});
