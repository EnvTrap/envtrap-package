// src/detection/HttpParser.ts
// HTTP request parsing and network-context formatting.
//
// Separated from fingerprint.ts because this is a network-layer concern,
// not a secret-detection concern. The scanner calls formatNetworkContext;
// fingerprint.ts stays focused on entropy math.

import { getSha256 } from './fingerprint.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HttpRequestDetails {
  method: string;
  url: string;
  host: string;
  headers: Record<string, string>;
  body: string;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parses a raw HTTP/1.1 request string into structured fields.
 * Returns null if the input doesn't look like a valid HTTP request.
 */
export function parseHttpRequest(raw: string): HttpRequestDetails | null {
  try {
    const lines = raw.split('\r\n');
    if (lines.length < 2) return null;

    const reqParts = lines[0].split(' ');
    if (reqParts.length < 2) return null;

    const method = reqParts[0];
    const url = reqParts[1];
    const headers: Record<string, string> = {};
    let host = '';
    let bodyIndex = -1;

    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') {
        bodyIndex = i + 1;
        break;
      }
      const colonIdx = lines[i].indexOf(': ');
      if (colonIdx !== -1) {
        const key = lines[i].slice(0, colonIdx);
        const val = lines[i].slice(colonIdx + 2);
        headers[key] = val;
        if (key.toLowerCase() === 'host') host = val;
      }
    }

    const body =
      bodyIndex !== -1 && bodyIndex < lines.length
        ? lines.slice(bodyIndex).join('\r\n')
        : '';

    return { method, url, host, headers, body };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Context formatter
// ---------------------------------------------------------------------------

/**
 * Builds a human-readable, AI-safe audit log for an intercepted HTTP request
 * that contains a secret value. All sensitive header values and body snippets
 * are redacted to SHA-256 hash prefixes.
 */
export function formatNetworkContext(content: string, secretValue: string): string {
  const parsed = parseHttpRequest(content);

  if (!parsed) {
    // Fallback: plain substring context
    const idx = content.indexOf(secretValue);
    if (idx === -1) return '';
    const hash = getSha256(secretValue);
    const hashStr = `[REDACTED: SHA256:${hash.slice(0, 8)}]`;
    const start = Math.max(0, idx - 40);
    const end = Math.min(content.length, idx + secretValue.length + 40);
    return content.slice(start, end).replace(secretValue, hashStr);
  }

  const hash = getSha256(secretValue);
  const hashStr = `[REDACTED: SHA256:${hash.slice(0, 8)}]`;

  const auditHeaders: string[] = [];
  for (const [key, val] of Object.entries(parsed.headers)) {
    const lk = key.toLowerCase();
    if (val.includes(secretValue)) {
      auditHeaders.push(`    ${key}: ${val.replace(secretValue, hashStr)}`);
    } else if (lk === 'authorization' || lk === 'cookie') {
      auditHeaders.push(`    ${key}: [REDACTED VALUE]`);
    } else {
      auditHeaders.push(`    ${key}: ${val}`);
    }
  }

  let bodySnippet = '';
  if (parsed.body) {
    if (parsed.body.includes(secretValue)) {
      const idx = parsed.body.indexOf(secretValue);
      const start = Math.max(0, idx - 20);
      const end = Math.min(parsed.body.length, idx + secretValue.length + 20);
      bodySnippet =
        `\n  Body Context:\n    ...${parsed.body.slice(start, end).replace(secretValue, hashStr)}...`;
    } else {
      bodySnippet = '\n  Body Context: (Present, no secret found in body)';
    }
  }

  return (
    `Outbound HTTPS Request Audited:\n` +
    `  Destination Host: ${parsed.host}\n` +
    `  Request Line:     ${parsed.method} ${parsed.url}\n` +
    `  Headers:\n${auditHeaders.join('\n')}` +
    bodySnippet
  );
}
