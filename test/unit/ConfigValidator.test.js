// test/unit/ConfigValidator.test.js
const test = require('node:test');
const assert = require('node:assert');
const { ConfigValidator } = require('../../dist/config/ConfigValidator.js');

test('ConfigValidator - validate clean configs', () => {
  const validator = new ConfigValidator();

  const validConfig = {
    channels: {
      stdout: 'warn',
      stderr: 'off',
      network: 'block',
      child_process: 'warn',
      dns: 'block'
    },
    exclusions: {
      domains: ['example.com'],
      paths: ['src/**/*.test.ts']
    },
    entropy: {
      threshold: 4.1,
      minLength: 16
    }
  };

  const errors = validator.validate(validConfig);
  assert.strictEqual(errors.length, 0);
});

test('ConfigValidator - validate bad configurations', () => {
  const validator = new ConfigValidator();

  const badConfig = {
    channels: {
      stdout: 'invalid_mode', // must fail
      stderr: 'warn'
    },
    exclusions: {
      domains: 'not-an-array' // must fail
    }
  };

  const errors = validator.validate(badConfig);
  assert.strictEqual(errors.length > 0, true);
  
  const stdoutError = errors.find(e => e.path === '$.channels.stdout');
  const domainsError = errors.find(e => e.path === '$.exclusions.domains');
  
  assert.notStrictEqual(stdoutError, undefined);
  assert.notStrictEqual(domainsError, undefined);
});
