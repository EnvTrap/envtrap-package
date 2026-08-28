// verify-proxy-env.mjs — quick verification script for NO_PROXY injection
const NO_PROXY  = process.env.NO_PROXY  ?? '(not set)';
const no_proxy  = process.env.no_proxy  ?? '(not set)';
const HTTPS     = process.env.HTTPS_PROXY ?? '(not set)';

process.stdout.write('=== envtrap proxy environment ===\n');
process.stdout.write('HTTPS_PROXY : ' + HTTPS + '\n');
process.stdout.write('NO_PROXY    : ' + NO_PROXY + '\n');
process.stdout.write('no_proxy    : ' + no_proxy + '\n');
process.stdout.write('=================================\n');
