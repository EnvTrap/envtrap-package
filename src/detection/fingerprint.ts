// src/detection/fingerprint.ts
// Core secret-detection primitives.
//
// Responsibilities (only):
//   - SHA-256 hashing
//   - Shannon entropy calculation
//   - looksLikeSecret() gate
//   - scanContent() — searches a string for known secret values
//   - extractContext() — builds a redacted snippet around a match
//
// HTTP parsing → HttpParser.ts
// Known token patterns → patterns.ts

import { createHash } from 'node:crypto';
import { DETERMINISTIC_PATTERNS } from './patterns.js';
import type { Secret } from '../types.js';

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/** Returns the hex SHA-256 digest of a string. */
export function getSha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/**
 * Computes the Shannon entropy of a string.
 * H = -Σ (f/n) * log2(f/n)
 * Returns a float in [0, log2(uniqueChars)].
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const n = str.length;
  for (const count of freq.values()) {
    const p = count / n;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// ---------------------------------------------------------------------------
// Secret gate
// ---------------------------------------------------------------------------

/**
 * Returns true if a value should be tracked as a secret candidate.
 * Deterministic regex patterns take priority over the entropy gate.
 */
export function looksLikeSecret(value: string, minLength = 12, minEntropy = 3.5): boolean {
  if (value.length < minLength) return false;

  for (const { pattern } of DETERMINISTIC_PATTERNS) {
    if (pattern.test(value)) return true;
  }

  return shannonEntropy(value) >= minEntropy;
}

// ---------------------------------------------------------------------------
// Content scanning
// ---------------------------------------------------------------------------

/**
 * Searches a content string for any known secret values.
 * Returns the names of matched secrets.
 *
 * The caller is responsible for clamping content to a safe size before
 * passing it here (see Scanner.ts).
 */
export function scanContent(
  content: string,
  secrets: Secret[],
  minLength = 12,
  minEntropy = 3.5,
): string[] {
  if (!content || content.length === 0) return [];

  const found: string[] = [];

  for (const { name, value } of secrets) {
    if (!looksLikeSecret(value, minLength, minEntropy)) continue;
    if (content.includes(value)) found.push(name);
  }

  return found;
}

// ---------------------------------------------------------------------------
// Context snippet
// ---------------------------------------------------------------------------

/**
 * Extracts a short context snippet around the first match of value in content.
 * The matched value itself is replaced with its SHA-256 hash prefix.
 */
export function extractContext(content: string, value: string, windowSize = 40): string {
  const idx = content.indexOf(value);
  if (idx === -1) return '';

  const start = Math.max(0, idx - windowSize);
  const end = Math.min(content.length, idx + value.length + windowSize);
  const snippet = content.slice(start, end);
  const hash = getSha256(value);

  return snippet.replace(value, `[REDACTED: SHA256:${hash.slice(0, 8)}]`);
}
