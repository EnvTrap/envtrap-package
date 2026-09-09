// test/fixtures/subprocess-execfile.js
const { execFile } = require('node:child_process');

execFile(process.execPath, ['-e', 'process.stdout.write("ARG_CB_OK")'], (err, stdout) => {
  if (err) throw err;
  process.stdout.write('\nRESULT1:' + stdout);
});

execFile(process.execPath, ['-e', 'process.stdout.write("OPT_CB_OK:" + (process.env.TEST_CUSTOM || ""))'], {
  env: { ...process.env, TEST_CUSTOM: 'HELLO' },
}, (err, stdout) => {
  if (err) throw err;
  process.stdout.write('\nRESULT2:' + stdout);
});
