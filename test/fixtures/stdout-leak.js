// test/fixtures/stdout-leak.js
const secret = process.env.TEST_SECRET_KEY || ['sk', 'test', 'fixture_secret_value_12345'].join('_');
console.log('App started with secret:', secret);
