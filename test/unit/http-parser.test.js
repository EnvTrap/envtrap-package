// test/unit/http-parser.test.js
const test = require('node:test');
const assert = require('node:assert');
const { parseHttpRequest, formatNetworkContext } = require('../../dist/detection/HttpParser.js');
const { getSha256 } = require('../../dist/detection/fingerprint.js');

test('HttpParser - parse standard requests (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)', () => {
  // GET
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

  // PUT with body
  const rawPut =
    'PUT /api/v2/items/42 HTTP/1.1\r\n' +
    'Host: backend.internal\r\n' +
    'Content-Type: application/json\r\n\r\n' +
    '{"active": true}';
  const parsedPut = parseHttpRequest(rawPut);
  assert.strictEqual(parsedPut.method, 'PUT');
  assert.strictEqual(parsedPut.body, '{"active": true}');

  // DELETE
  const rawDel = 'DELETE /api/v2/items/42 HTTP/1.1\r\nHost: backend.internal\r\n\r\n';
  const parsedDel = parseHttpRequest(rawDel);
  assert.strictEqual(parsedDel.method, 'DELETE');
  assert.strictEqual(parsedDel.body, '');

  // PATCH
  const rawPatch = 'PATCH /users/me HTTP/1.1\r\nHost: api.example.com\r\n\r\n{"name":"alice"}';
  const parsedPatch = parseHttpRequest(rawPatch);
  assert.strictEqual(parsedPatch.method, 'PATCH');
  assert.strictEqual(parsedPatch.body, '{"name":"alice"}');

  // HEAD
  const rawHead = 'HEAD /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n';
  const parsedHead = parseHttpRequest(rawHead);
  assert.strictEqual(parsedHead.method, 'HEAD');

  // OPTIONS
  const rawOpt = 'OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n';
  const parsedOpt = parseHttpRequest(rawOpt);
  assert.strictEqual(parsedOpt.method, 'OPTIONS');
});

test('HttpParser - parse post request with multiline body', () => {
  const rawPost =
    'POST /v1/refunds HTTP/1.1\r\n' +
    'Host: api.stripe.com\r\n' +
    'Content-Length: 30\r\n\r\n' +
    'line1=val1\r\nline2=val2\r\nline3=val3';

  const parsed = parseHttpRequest(rawPost);
  assert.notStrictEqual(parsed, null);
  assert.strictEqual(parsed.method, 'POST');
  assert.strictEqual(parsed.body, 'line1=val1\r\nline2=val2\r\nline3=val3');
});

test('HttpParser - parse malformed requests', () => {
  assert.strictEqual(parseHttpRequest(''), null);
  assert.strictEqual(parseHttpRequest('RANDOM_JUNK_DATA'), null);
  assert.strictEqual(parseHttpRequest('ONLYMETHOD'), null);
  assert.strictEqual(parseHttpRequest('GET\r\nHost: api.stripe.com'), null); // Only 1 part in req line
});

test('HttpParser - format network context audits with secret in headers and body', () => {
  const secret = ['sk', 'live', 'secret123'].join('_');
  const hash = getSha256(secret).slice(0, 8);
  const rawRequest =
    'POST /v1/charges HTTP/1.1\r\n' +
    'Host: api.stripe.com\r\n' +
    `Authorization: Bearer ${secret}\r\n` +
    'Cookie: session_id=unrelated_session_token\r\n' +
    'X-Custom: normal_header_value\r\n' +
    '\r\n' +
    `{"amount": 2000, "token": "${secret}"}`;

  const formatted = formatNetworkContext(rawRequest, secret);
  assert.match(formatted, /Outbound HTTPS Request Audited:/);
  assert.match(formatted, /Destination Host: api\.stripe\.com/);
  assert.match(formatted, /Request Line:\s+POST \/v1\/charges/);
  // Secret in header is redacted with SHA256
  assert.match(formatted, new RegExp(`Authorization: Bearer \\[REDACTED: SHA256:${hash}\\]`));
  // Unrelated sensitive headers (Cookie) are replaced with [REDACTED VALUE]
  assert.match(formatted, /Cookie: \[REDACTED VALUE\]/);
  // Normal headers are preserved
  assert.match(formatted, /X-Custom: normal_header_value/);
  // Body context has snippet
  assert.match(formatted, /Body Context:/);
  assert.match(formatted, new RegExp(`\\[REDACTED: SHA256:${hash}\\]`));
});

test('HttpParser - format network context when body has no secret', () => {
  const secret = 'my_secret_token_xyz';
  const rawRequest =
    'POST /v1/charges HTTP/1.1\r\n' +
    'Host: api.stripe.com\r\n' +
    `Authorization: Bearer ${secret}\r\n` +
    '\r\n' +
    '{"amount": 2000, "currency": "usd"}';

  const formatted = formatNetworkContext(rawRequest, secret);
  assert.match(formatted, /Body Context: \(Present, no secret found in body\)/);
});

test('HttpParser - format network context fallback for non-HTTP content', () => {
  const secret = 'raw_tcp_payload_secret_123';
  const hash = getSha256(secret).slice(0, 8);

  // Content containing secret but not valid HTTP
  const nonHttp = `SOME_RAW_PROTOCOL_HEADER: 0xDEADBEEF ${secret} FOOTER_CRC`;
  const formatted = formatNetworkContext(nonHttp, secret);
  assert.strictEqual(formatted.includes(secret), false);
  assert.match(formatted, new RegExp(`\\[REDACTED: SHA256:${hash}\\]`));

  // Non-HTTP content without secret returns empty string
  assert.strictEqual(formatNetworkContext(nonHttp, 'non_matching_secret'), '');
});
