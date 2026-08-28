// src/domain/SecretMatcher.ts
// Finds which loaded secrets appear in a given content string.
// Single responsibility: substring search gated by the looksLikeSecret() heuristic.

import { looksLikeSecret } from '../detection/fingerprint.js';
import type { Secret } from '../types.js';
import type { EntropyConfig } from '../config/ConfigTypes.js';

export class SecretMatcher {
  constructor(
    private readonly secrets: readonly Secret[],
    private readonly entropy: EntropyConfig,
  ) {}

  /** Returns every secret whose value appears in content. */
  findIn(content: string): readonly Secret[] {
    return this.secrets.filter((s) => this.isCandidate(s) && content.includes(s.value));
  }

  /** Returns secrets whose name exists as a key in env with matching value. */
  findMatchingKeys(env: Record<string, string | undefined>): readonly Secret[] {
    return this.secrets.filter((s) => {
      return Object.prototype.hasOwnProperty.call(env, s.name) && env[s.name] === s.value;
    });
  }

  private isCandidate(secret: Secret): boolean {
    return looksLikeSecret(secret.value, this.entropy.minLength, this.entropy.threshold);
  }
}
