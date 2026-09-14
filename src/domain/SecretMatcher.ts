// src/domain/SecretMatcher.ts
// Finds which loaded secrets appear in a given content string.
// Single responsibility: substring search gated by the looksLikeSecret() heuristic.

import { looksLikeSecret } from '../detection/fingerprint.js';
import type { Secret } from '../types.js';
import { DEFAULT_CONFIG, type EntropyConfig } from '../config/ConfigTypes.js';

interface VariantEntry {
  readonly pattern: string;
  readonly secret: Secret;
}

export class SecretMatcher {
  private readonly variants: VariantEntry[] = [];
  private readonly entropy: EntropyConfig;
  private readonly minVariantLength: number;

  constructor(
    private readonly secrets: readonly Secret[],
    entropy?: EntropyConfig,
  ) {
    this.entropy = entropy ?? DEFAULT_CONFIG.entropy;
    this.indexEncodedVariants();
    this.minVariantLength = this.variants.length > 0
      ? Math.min(...this.variants.map((v) => v.pattern.length))
      : Infinity;
  }

  /** Returns every secret whose verbatim value or encoded representation appears in content. */
  findIn(content: string): readonly Secret[] {
    if (!content) return [];

    const matchedSecrets = new Set<Secret>();

    // 1. Direct raw value inclusion
    for (const s of this.secrets) {
      if (this.isCandidate(s) && content.includes(s.value)) {
        matchedSecrets.add(s);
      }
    }

    // 2. Encoded representation inclusion (Base64, URL-encode, Hex, JSON-escaped)
    if (content.length >= this.minVariantLength) {
      for (const { pattern, secret } of this.variants) {
        if (content.includes(pattern)) {
          matchedSecrets.add(secret);
        }
      }
    }

    return Array.from(matchedSecrets);
  }

  /** Returns secrets whose name exists as a key in env with matching value. */
  findMatchingKeys(env: Record<string, string | undefined>): readonly Secret[] {
    return this.secrets.filter((s) => {
      return Object.prototype.hasOwnProperty.call(env, s.name) && env[s.name] === s.value;
    });
  }

  private isCandidate(secret: Secret): boolean {
    if (secret.source === 'file') {
      return typeof secret.value === 'string' && secret.value.trim().length >= 4;
    }
    return looksLikeSecret(secret.value, this.entropy.minLength, this.entropy.threshold);
  }

  private indexEncodedVariants(): void {
    const minLen = Math.max(6, this.entropy.minLength);
    const seenPatterns = new Set<string>();

    for (const s of this.secrets) {
      if (!this.isCandidate(s)) continue;
      const val = s.value;
      if (val.length < minLen) continue;

      const candidates = new Set<string>();

      // Base64 standard & URL-safe & unpadded
      try {
        const b64 = Buffer.from(val, 'utf-8').toString('base64');
        if (b64 && b64 !== val) {
          candidates.add(b64);
          const unpadded = b64.replace(/=+$/, '');
          if (unpadded && unpadded !== val) candidates.add(unpadded);
        }
        const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        if (b64url && b64url !== val) candidates.add(b64url);
      } catch { /* ignore */ }

      // URL-encoded (uppercase and lowercase percent-escapes)
      try {
        const urlEnc = encodeURIComponent(val);
        if (urlEnc && urlEnc !== val) {
          candidates.add(urlEnc);
          const lowerHex = urlEnc.replace(/%[0-9A-Fa-f]{2}/g, (m) => m.toLowerCase());
          if (lowerHex !== val) candidates.add(lowerHex);
          const upperHex = urlEnc.replace(/%[0-9A-Fa-f]{2}/g, (m) => m.toUpperCase());
          if (upperHex !== val) candidates.add(upperHex);
        }
      } catch { /* ignore */ }

      // Hex encoded
      try {
        const hex = Buffer.from(val, 'utf-8').toString('hex');
        if (hex && hex !== val) {
          candidates.add(hex);
          candidates.add(hex.toUpperCase());
        }
      } catch { /* ignore */ }

      // JSON stringified (standard & escaped forward slashes)
      try {
        const jsonStr = JSON.stringify(val);
        const innerJson = jsonStr.slice(1, -1);
        if (innerJson && innerJson !== val) {
          candidates.add(innerJson);
        }
        if (val.includes('/')) {
          candidates.add(val.replace(/\//g, '\\/'));
        }
        if (innerJson && innerJson.includes('/')) {
          candidates.add(innerJson.replace(/\//g, '\\/'));
        }
      } catch { /* ignore */ }

      for (const pattern of candidates) {
        if (pattern.length >= 4) {
          const dedupeKey = `${pattern}:${s.name}`;
          if (!seenPatterns.has(dedupeKey)) {
            seenPatterns.add(dedupeKey);
            this.variants.push({ pattern, secret: s });
          }
        }
      }
    }
  }
}
