// src/detection/patterns.ts
// Deterministic regex patterns for well-known secret formats.
//
// Separated from fingerprint.ts so they can be imported independently
// (e.g. by network scanners or external tools) without pulling in
// entropy math or SHA-256 utilities.

export interface TokenPattern {
  name: string;
  pattern: RegExp;
}

/**
 * Patterns that bypass entropy/length thresholds — if matched, always flag.
 * Listed roughly by specificity (most specific first).
 */
export const DETERMINISTIC_PATTERNS: TokenPattern[] = [
  { name: 'Stripe Secret Key',               pattern: /sk_(live|test)_[a-zA-Z0-9]{24,}/ },
  { name: 'AWS Access Key ID',               pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub Personal Access Token',    pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'SendGrid API Key',                pattern: /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/ },
  { name: 'Slack Bot Token',                 pattern: /xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}/ },
  { name: 'Generic Bearer Token',            pattern: /Bearer\s+[a-zA-Z0-9\-._~+/]{20,}/ },
];
