// test/fixtures/stderr-leak.js
const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');
process.stderr.write(`Fatal error: authorization failed with token ${secret}\n`);
