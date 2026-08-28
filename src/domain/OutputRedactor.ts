// src/domain/OutputRedactor.ts
// Replaces known secret values in a string with SHA-256 hash placeholders.
// Single responsibility: redact — does not scan, detect, or report.

import { getSha256 } from '../detection/fingerprint.js';
import type { Secret } from '../types.js';

export class OutputRedactor {
  constructor(private readonly secrets: readonly Secret[]) {}

  /** Returns a copy of text with every known secret value replaced by its hash. */
  redact(text: string): string {
    return this.secrets.reduce((acc, secret) => this.redactOne(acc, secret), text);
  }

  private redactOne(text: string, secret: Secret): string {
    if (!text.includes(secret.value)) return text;
    const tag = `[REDACTED: SHA256:${getSha256(secret.value).slice(0, 8)}]`;
    return text.split(secret.value).join(tag);
  }
}
