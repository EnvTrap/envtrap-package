// test/unit/reporting.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ReportWriter } = require('../../dist/reporting/ReportWriter.js');
const { FileEventLogger } = require('../../dist/reporting/FileEventLogger.js');
const { LeakAlertPrinter } = require('../../dist/reporting/LeakAlertPrinter.js');
const { RunSummaryPrinter } = require('../../dist/reporting/RunSummaryPrinter.js');

test('ReportWriter - serializes events to JSON without plaintext secrets', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envtrap-report-test-'));
  try {
    const writer = new ReportWriter(tmpDir);
    const secretValue = ['sk', 'live', 'supersecretpayload123456'].join('_');
    const events = [
      {
        secret: { name: 'STRIPE_KEY', value: secretValue, source: 'env' },
        channel: 'network',
        context: 'POST /v1/charges Host: api.stripe.com',
        timestamp: 1700000000000
      }
    ];

    writer.write(events);

    const reportFile = path.join(tmpDir, '.envtrap-report.json');
    assert.strictEqual(fs.existsSync(reportFile), true);

    const content = fs.readFileSync(reportFile, 'utf-8');
    const parsed = JSON.parse(content);

    assert.strictEqual(parsed.length, 1);
    assert.strictEqual(parsed[0].secretName, 'STRIPE_KEY');
    assert.strictEqual(parsed[0].channel, 'network');
    assert.strictEqual(parsed[0].sha256.length, 64);
    assert.strictEqual(parsed[0].timestamp, 1700000000000);

    // CRITICAL: Plaintext secret MUST NOT exist in report
    assert.strictEqual(content.includes(secretValue), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('FileEventLogger - appends JSONL lines and creates directory if needed', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envtrap-log-test-'));
  const logFile = path.join(tmpDir, 'nested', 'events.jsonl');
  try {
    const logger = new FileEventLogger(logFile);
    const secretValue = ['sk', 'live', 'loggersecret123456'].join('_');
    const event = {
      secret: { name: 'API_TOKEN', value: secretValue, source: 'env' },
      channel: 'stdout',
      context: 'Logging token',
      timestamp: 1700000001000
    };

    logger.report(event);
    logger.report({ ...event, channel: 'stderr' });

    assert.strictEqual(fs.existsSync(logFile), true);
    const lines = fs.readFileSync(logFile, 'utf-8').trim().split('\n');
    assert.strictEqual(lines.length, 2);

    const first = JSON.parse(lines[0]);
    assert.strictEqual(first.secretName, 'API_TOKEN');
    assert.strictEqual(first.channel, 'stdout');
    assert.strictEqual(first.sha256.length, 64);

    // Does nothing gracefully when logFilePath is null
    const nullLogger = new FileEventLogger(null);
    nullLogger.report(event); // Should not throw
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('LeakAlertPrinter - quiet mode suppresses output', () => {
  const oldError = console.error;
  let printed = false;
  console.error = () => { printed = true; };

  try {
    const printer = new LeakAlertPrinter(true);
    printer.report({
      secret: { name: 'KEY', value: 'secret1234567890', source: 'env' },
      channel: 'stdout',
      context: 'context text',
      timestamp: Date.now()
    });
    assert.strictEqual(printed, false);
  } finally {
    console.error = oldError;
  }
});

test('RunSummaryPrinter - formats summary for zero vs multiple events', () => {
  const oldError = console.error;
  const logged = [];
  console.error = (...args) => logged.push(args.join(' '));

  try {
    const summary = new RunSummaryPrinter();

    // 0 events
    summary.print([]);
    assert.ok(logged.some(l => l.includes('No secret leaks detected')));

    // Multiple events
    logged.length = 0;
    const events = [
      { secret: { name: 'K1', value: 'v1', source: 'env' }, channel: 'stdout', context: '', timestamp: 1 },
      { secret: { name: 'K2', value: 'v2', source: 'env' }, channel: 'stdout', context: '', timestamp: 2 },
      { secret: { name: 'K3', value: 'v3', source: 'env' }, channel: 'network', context: '', timestamp: 3 }
    ];
    summary.print(events);
    assert.ok(logged.some(l => l.includes('3 leak event(s) detected!')));
    assert.ok(logged.some(l => l.includes('STDOUT') && l.includes('2 leak(s)')));
    assert.ok(logged.some(l => l.includes('NETWORK') && l.includes('1 leak(s)')));
  } finally {
    console.error = oldError;
  }
});
