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

  constructor(
    private readonly secrets: readonly Secret[],
    entropy?: EntropyConfig,
  ) {
    this.entropy = entropy ?? DEFAULT_CONFIG.entropy;
    this.indexEncodedVariants();
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
    for (const { pattern, secret } of this.variants) {
      if (content.includes(pattern)) {
        matchedSecrets.add(secret);
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
    for (const s of this.secrets) {
      if (!this.isCandidate(s)) continue;
      const val = s.value;
      if (val.length < 6) continue;

      const candidates = new Set<string>();

      // Base64 standard & URL-safe
      try {
        const b64 = Buffer.from(val, 'utf-8').toString('base64');
        if (b64 && b64 !== val) candidates.add(b64);
        const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        if (b64url && b64url !== val) candidates.add(b64url);
      } catch { /* ignore */ }

      // URL-encoded
      try {
        const urlEnc = encodeURIComponent(val);
        if (urlEnc && urlEnc !== val) candidates.add(urlEnc);
      } catch { /* ignore */ }

      // Hex encoded
      try {
        const hex = Buffer.from(val, 'utf-8').toString('hex');
        if (hex && hex !== val) {
          candidates.add(hex);
          candidates.add(hex.toUpperCase());
        }
      } catch { /* ignore */ }

      // JSON stringified
      try {
        const jsonStr = JSON.stringify(val);
        const innerJson = jsonStr.slice(1, -1);
        if (innerJson && innerJson !== val) candidates.add(innerJson);
      } catch { /* ignore */ }

      for (const pattern of candidates) {
        this.variants.push({ pattern, secret: s });
      }
    }
  }
}
