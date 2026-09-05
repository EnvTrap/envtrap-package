// test/integration/mitm.test.js
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const tls = require('node:tls');
const { CertificateAuthority } = require('../../dist/mitm/CertificateAuthority.js');
const { MitmServer } = require('../../dist/mitm/MitmServer.js');

// ============================================================================
// CertificateAuthority Tests
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
        return { leaked: true, blocked: true, secret: { name: 'MOCK_SECRET', value: 'secret_key_99999', source: 'env' } };
      }
      return { leaked: false, blocked: false };
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

test('MitmServer - allowed domain bypasses interception', async () => {
  let targetServer;
  try {
    targetServer = http.createServer((req, res) => {
      res.writeHead(200);
      res.end('allowed target response');
    });
    const targetPort = await new Promise(r => targetServer.listen(0, '127.0.0.1', () => r(targetServer.address().port)));

    const mockScanner = {
      scan: () => {
        throw new Error('Scanner should NOT be called for excluded domain');
      }
    };
    const ca = new CertificateAuthority();
    const config = {
      channels: { stdout: 'warn', stderr: 'warn', network: 'block', child_process: 'warn', dns: 'block' },
      exclusions: { domains: ['127.0.0.1'], paths: [] },
      entropy: { threshold: 3.5, minLength: 12 },
      quiet: true,
      logFile: null
    };
    const mitm = new MitmServer(ca, mockScanner, { warn: () => {}, info: () => {} }, config, false);
    const proxyPort = await mitm.start();

    // Make request with secret in body to excluded domain
    const resp = await makeProxyRequest(proxyPort, targetPort, 'POST', '/test', {}, 'secret_key_99999');
    assert.strictEqual(resp, 'allowed target response');

    await mitm.stop();
  } finally {
    if (targetServer) targetServer.close();
  }
});

test('MitmServer - network channel mode off forwards without blocking', async () => {
  let targetServer;
  try {
    targetServer = http.createServer((req, res) => {
      res.writeHead(200);
      res.end('off mode response');
    });
    const targetPort = await new Promise(r => targetServer.listen(0, '127.0.0.1', () => r(targetServer.address().port)));

    const mockScanner = {
      scan: () => {
        throw new Error('Scanner should NOT be called when mode is off');
      }
    };
    const ca = new CertificateAuthority();
    const config = {
      channels: { stdout: 'warn', stderr: 'warn', network: 'off', child_process: 'warn', dns: 'block' },
      exclusions: { domains: [], paths: [] },
      entropy: { threshold: 3.5, minLength: 12 },
      quiet: true,
      logFile: null
    };
    const mitm = new MitmServer(ca, mockScanner, { warn: () => {}, info: () => {} }, config, false);
    const proxyPort = await mitm.start();

    const resp = await makeProxyRequest(proxyPort, targetPort, 'POST', '/test', {}, 'secret_key_99999');
    assert.strictEqual(resp, 'off mode response');

    await mitm.stop();
  } finally {
    if (targetServer) targetServer.close();
  }
});

test('MitmServer - CONNECT tunnel and TLS leak interception', async () => {
  const ca = new CertificateAuthority();
  const caMaterials = ca.initCA();
  let tlsScanned = false;

  const mockScanner = {
    scan: (content, channel) => {
      if (content.includes('tls_secret_token')) {
        tlsScanned = true;
        return { leaked: true, blocked: true };
      }
      return { leaked: false, blocked: false };
    }
  };

  const config = {
    channels: { stdout: 'warn', stderr: 'warn', network: 'block', child_process: 'warn', dns: 'block' },
    exclusions: { domains: [], paths: [] },
    entropy: { threshold: 3.5, minLength: 12 },
    quiet: true,
    logFile: null
  };

  const mitm = new MitmServer(ca, mockScanner, { warn: () => {}, info: () => {} }, config, false);
  const proxyPort = await mitm.start();

  try {
    await new Promise((resolve, reject) => {
      const connectReq = http.request({
        host: '127.0.0.1',
        port: proxyPort,
        method: 'CONNECT',
        path: 'localhost:8443'
      });

      connectReq.on('connect', (res, socket) => {
        assert.strictEqual(res.statusCode, 200);

        const tlsSocket = tls.connect({
          socket: socket,
          servername: 'localhost',
          ca: caMaterials.certPem,
          rejectUnauthorized: true
        }, () => {
          tlsSocket.write('POST /api HTTP/1.1\r\nHost: localhost\r\n\r\ntls_secret_token');
        });

        tlsSocket.on('close', () => {
          assert.strictEqual(tlsScanned, true);
          resolve();
        });
        tlsSocket.on('error', () => {
          assert.strictEqual(tlsScanned, true);
          resolve();
        });
      });

      connectReq.on('error', reject);
      connectReq.end();
    });
  } finally {
    await mitm.stop();
  }
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
