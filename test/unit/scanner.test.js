// test/unit/scanner.test.js
const test = require('node:test');
const assert = require('node:assert');
const { Scanner } = require('../../dist/scanner/Scanner.js');
const { SecretMatcher } = require('../../dist/domain/SecretMatcher.js');
const { DEFAULT_CONFIG } = require('../../dist/config/ConfigTypes.js');

test('Scanner - scan detects secrets and respects channel modes', () => {
  const fakeStripe = ['sk', 'live', '1234567890abcdef123456'].join('_');
  const secrets = [
    { name: 'STRIPE_KEY', value: fakeStripe, source: 'env' },
    { name: 'AWS_KEY', value: 'AKIAIOSFODNN7EXAMPLE', source: 'env' }
  ];
  const matcher = new SecretMatcher(secrets, DEFAULT_CONFIG.entropy);

  const reportedEvents = [];
  const mockReporter = {
    report: (event) => reportedEvents.push(event)
  };

  // 1. Channel mode: block
  const blockConfig = {
    ...DEFAULT_CONFIG,
    channels: { ...DEFAULT_CONFIG.channels, network: 'block' }
  };
  const blockScanner = new Scanner(matcher, blockConfig, mockReporter);

  const blockRes = blockScanner.scan(`POST / HTTP/1.1\r\nAuthorization: Bearer ${fakeStripe}\r\n\r\n`, 'network');
  assert.strictEqual(blockRes.leaked, true);
  assert.strictEqual(blockRes.blocked, true);
  assert.strictEqual(reportedEvents.length, 1);
  assert.strictEqual(reportedEvents[0].secret.name, 'STRIPE_KEY');

  // 2. Channel mode: warn
  reportedEvents.length = 0;
  const warnConfig = {
    ...DEFAULT_CONFIG,
    channels: { ...DEFAULT_CONFIG.channels, stdout: 'warn' }
  };
  const warnScanner = new Scanner(matcher, warnConfig, mockReporter);

  const warnRes = warnScanner.scan('User key is AKIAIOSFODNN7EXAMPLE', 'stdout');
  assert.strictEqual(warnRes.leaked, true);
  assert.strictEqual(warnRes.blocked, false);
  assert.strictEqual(reportedEvents.length, 1);
  assert.strictEqual(reportedEvents[0].secret.name, 'AWS_KEY');

  // 3. Channel mode: off
  reportedEvents.length = 0;
  const offConfig = {
    ...DEFAULT_CONFIG,
    channels: { ...DEFAULT_CONFIG.channels, stdout: 'off' }
  };
  const offScanner = new Scanner(matcher, offConfig, mockReporter);

  const offRes = offScanner.scan('User key is AKIAIOSFODNN7EXAMPLE', 'stdout');
  assert.strictEqual(offRes.leaked, false);
  assert.strictEqual(offRes.blocked, false);
  assert.strictEqual(reportedEvents.length, 0);
});

test('Scanner - deduplicates repeated leaks on the same channel', () => {
  const fakeStripe = ['sk', 'live', '1234567890abcdef123456'].join('_');
  const secrets = [
    { name: 'STRIPE_KEY', value: fakeStripe, source: 'env' }
  ];
  const matcher = new SecretMatcher(secrets, DEFAULT_CONFIG.entropy);
  const reportedEvents = [];
  const mockReporter = { report: (e) => reportedEvents.push(e) };

  const scanner = new Scanner(matcher, DEFAULT_CONFIG, mockReporter);

  // Scan same content 5 times
  for (let i = 0; i < 5; i++) {
    scanner.scan(`Leaking ${fakeStripe}`, 'stdout');
  }

  // Reporter should only have been called ONCE due to DedupCache
  assert.strictEqual(reportedEvents.length, 1);
  assert.strictEqual(scanner.getEvents().length, 1);

  // But scanning on a different channel records a new event
  scanner.scan(`Leaking ${fakeStripe}`, 'stderr');
  assert.strictEqual(reportedEvents.length, 2);
  assert.strictEqual(scanner.getEvents().length, 2);
});

test('Scanner - checkChildEnv inspects subprocess environment', () => {
  const secrets = [
    { name: 'DATABASE_URL', value: 'postgres://user:pass1234@db:5432/prod', source: 'env' },
    { name: 'GITHUB_TOKEN', value: 'ghp_' + 'A'.repeat(36), source: 'env' }
  ];
  const matcher = new SecretMatcher(secrets);
  const reportedEvents = [];
  const mockReporter = { report: (e) => reportedEvents.push(e) };

  const scanner = new Scanner(matcher, DEFAULT_CONFIG, mockReporter);

  const cleanEnv = { PATH: '/usr/bin', NODE_ENV: 'production' };
  const cleanRes = scanner.checkChildEnv(cleanEnv);
  assert.strictEqual(cleanRes.leaked, false);

  const dirtyEnv = { PATH: '/usr/bin', DATABASE_URL: 'postgres://user:pass1234@db:5432/prod' };
  const dirtyRes = scanner.checkChildEnv(dirtyEnv);
  assert.strictEqual(dirtyRes.leaked, true);
  assert.strictEqual(reportedEvents.length, 1);
  assert.strictEqual(reportedEvents[0].secret.name, 'DATABASE_URL');
  assert.strictEqual(reportedEvents[0].channel, 'child_process');
});
