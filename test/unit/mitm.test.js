// test/unit/mitm.test.js
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const { parseHttpRequest, formatNetworkContext } = require('../../dist/detection/HttpParser.js');
const { CertificateAuthority } = require('../../dist/mitm/CertificateAuthority.js');
const { MitmServer } = require('../../dist/mitm/MitmServer.js');

// ============================================================================
// HttpParser Unit Tests
// ============================================================================
test('HttpParser - parse standard requests', () => {
  const rawGet = 
    'GET /v1/charges?limit=3 HTTP/1.1\r\n' +
    'Host: api.stripe.com\r\n' +
    'Authorization: Bearer my_secret_token_123\r\n' +
    'Connection: close\r\n\r\n';

  const parsed = parseHttpRequest(rawGet);
  assert.notStrictEqual(parsed, null);
  assert.strictEqual(parsed.method, 'GET');
  assert.strictEqual(parsed.url, '/v1/charges?limit=3');
  assert.strictEqual(parsed.host, 'api.stripe.com');
  assert.strictEqual(parsed.headers['Authorization'], 'Bearer my_secret_token_123');
  assert.strictEqual(parsed.body, '');
});

test('HttpParser - parse post request with body', () => {
  const rawPost =
    'POST /v1/refunds HTTP/1.1\r\n' +
    'Host: api.stripe.com\r\n' +
    'Content-Length: 15\r\n\r\n' +
    'charge=ch_123456';

  const parsed = parseHttpRequest(rawPost);
  assert.notStrictEqual(parsed, null);
  assert.strictEqual(parsed.method, 'POST');
  assert.strictEqual(parsed.body, 'charge=ch_123456');
});

test('HttpParser - parse malformed requests', () => {
  assert.strictEqual(parseHttpRequest(''), null);
  assert.strictEqual(parseHttpRequest('NOT-HTTP-LINE\r\n\r\n'), null);
});

test('HttpParser - format network context audits', () => {
  const rawGet = 
    'GET /v1/charges HTTP/1.1\r\n' +
    'Host: api.stripe.com\r\n' +
    'Authorization: Bearer ' + 'sk_test_' + 'my_stripe_secret_123\r\n\r\n';

  const audit = formatNetworkContext(rawGet, 'sk_test_' + 'my_stripe_secret_123');
  assert.match(audit, /Destination Host: api.stripe.com/);
  assert.match(audit, /Request Line:     GET \/v1\/charges/);
  assert.match(audit, /Authorization: Bearer \[REDACTED: SHA256:[a-f0-9]{8}\]/);
});

// ============================================================================
// CertificateAuthority Unit Tests
// ============================================================================
test('CertificateAuthority - key generation & signing', () => {
  const ca = new CertificateAuthority();
  const materials = ca.initCA();

  // Root cert should exist
  assert.notStrictEqual(materials.certPem, undefined);
  assert.notStrictEqual(materials.certPath, undefined);

  // Dynamic signing of domain certificates
  const domainCert = ca.generateDomainCert('api.stripe.com');
  assert.notStrictEqual(domainCert, undefined);
  assert.notStrictEqual(domainCert.certPem, undefined);
  assert.notStrictEqual(domainCert.keyPem, undefined);

  // Cached hit validation (returns same object)
  const cachedCert = ca.generateDomainCert('api.stripe.com');
  assert.strictEqual(domainCert, cachedCert);
});

// ============================================================================
// MitmServer Live Interception Tests (Rigorous Loopback Testing)
// ============================================================================
test('MitmServer - live proxying & leak interceptions', async (t) => {
  let targetPort;
  let proxyPort;
  let targetServer;
  let proxyServer;
  
  let scannedPayloads = [];
  let blockedCount = 0;

  const mockScanner = {
    scan: (content, channel) => {
      scannedPayloads.push({ content, channel });
      if (content.includes('secret_key_99999')) {
        blockedCount++;
        return { hasSecret: true, secretName: 'MOCK_SECRET', value: 'secret_key_99999' };
      }
      return { hasSecret: false };
    }
  };

  const mockReporter = {
    warn: () => {},
    info: () => {}
  };

  const config = {
    channels: { stdout: 'warn', stderr: 'warn', network: 'block', child_process: 'warn', dns: 'block' },
    exclusions: { domains: [], paths: [] },
    entropy: { threshold: 3.5, minLength: 12 },
    quiet: true,
    logFile: null
  };

  // 1. Setup local target server
  targetServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('target response: ' + body);
    });
  });

  await new Promise(resolve => {
    targetServer.listen(0, '127.0.0.1', () => {
      targetPort = targetServer.address().port;
      resolve();
    });
  });

  // 2. Setup MitmServer proxy
  const ca = new CertificateAuthority();
  ca.initCA();
  proxyServer = new MitmServer(ca, mockScanner, mockReporter, config, false);
  proxyPort = await proxyServer.start();

  // Clean cleanup hook
  t.after(async () => {
    await proxyServer.stop();
    await new Promise(resolve => targetServer.close(resolve));
  });

  // Test Case A: Plain HTTP request proxying (clean payload)
  await t.test('Clean HTTP request goes through', async () => {
    scannedPayloads = [];
    const responseText = await makeProxyRequest(proxyPort, targetPort, 'GET', '/hello', {}, 'clean_payload');
    assert.strictEqual(responseText, 'target response: clean_payload');
    assert.strictEqual(scannedPayloads.length > 0, true);
    assert.strictEqual(blockedCount, 0);
  });

  // Test Case B: HTTP Secret Interception in Headers
  await t.test('HTTP request with secret in headers is blocked', async () => {
    blockedCount = 0;
    try {
      await makeProxyRequest(proxyPort, targetPort, 'GET', '/secret', { 'X-Api-Key': 'secret_key_99999' }, 'clean');
      assert.fail('Expected request to fail due to proxy block');
    } catch (err) {
      assert.ok(err);
      assert.strictEqual(blockedCount > 0, true);
    }
  });

  // Test Case C: HTTP Secret Interception in Body
  await t.test('HTTP request with secret in body payload is blocked', async () => {
    blockedCount = 0;
    try {
      await makeProxyRequest(proxyPort, targetPort, 'POST', '/submit', {}, 'my key is secret_key_99999');
      assert.fail('Expected request to fail due to proxy block');
    } catch (err) {
      assert.ok(err);
      assert.strictEqual(blockedCount > 0, true);
    }
  });

  // Test Case D: HTTP Secret Interception in URL Query
  await t.test('HTTP request with secret in URL path/query is blocked', async () => {
    blockedCount = 0;
    try {
      await makeProxyRequest(proxyPort, targetPort, 'GET', '/leak?token=secret_key_99999', {}, 'clean');
      assert.fail('Expected request to fail due to proxy block');
    } catch (err) {
      assert.ok(err);
      assert.strictEqual(blockedCount > 0, true);
    }
  });

  // Test Case E: Clamped backpressure upload check
  await t.test('Large uploads are scanned up to limit without crash', async () => {
    // Generate 11KB payload (under 1MB, but verifies scan buffers correctly)
    const largePayload = 'A'.repeat(11000) + 'secret_key_99999';
    blockedCount = 0;
    try {
      await makeProxyRequest(proxyPort, targetPort, 'POST', '/upload', {}, largePayload);
      assert.fail('Expected large upload containing secret to be blocked');
    } catch (err) {
      assert.ok(err);
      assert.strictEqual(blockedCount > 0, true);
    }
  });

  // Test Case F: Upstream connection failure check
  await t.test('Gracefully returns 502 Bad Gateway on connection failures', async () => {
    const closedPort = 59999; // Assume nothing binds here
    const options = {
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: `http://127.0.0.1:${closedPort}/`,
      headers: { Host: `127.0.0.1:${closedPort}` }
    };
    
    await new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        assert.strictEqual(res.statusCode, 502);
        resolve();
      });
      req.on('error', reject);
      req.end();
    });
  });
});

// Helper function to issue requests through the loopback proxy
function makeProxyRequest(proxyPort, targetPort, method, path, headers = {}, body = '') {
  const options = {
    host: '127.0.0.1',
    port: proxyPort,
    method: method,
    path: `http://127.0.0.1:${targetPort}${path}`,
    headers: {
      Host: `127.0.0.1:${targetPort}`,
      ...headers
    }
  };

  if (body) {
    options.headers['Content-Length'] = Buffer.byteLength(body);
  }

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP Error Response: ${res.statusCode}`));
        } else {
          resolve(data);
        }
      });
    });

    req.on('error', (err) => reject(err));
    if (body) {
      req.write(body);
    }
    req.end();
  });
}
