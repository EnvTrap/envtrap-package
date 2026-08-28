// src/secrets/SecretSourceComposer.ts
// Composes N ISecretSource instances, merges their results, and deduplicates
// by value (same secret from two sources is only tracked once).
// Single responsibility: aggregation + deduplication.

import type { ISecretSource } from '../ports/ISecretSource.js';
import type { Secret } from '../types.js';

export class SecretSourceComposer {
  constructor(private readonly sources: readonly ISecretSource[]) {}

  /** Load all secrets from all sources, deduplicate by name and value. */
  load(): Secret[] {
    const seenValues = new Set<string>();
    const seenNames = new Set<string>();
    const secrets: Secret[] = [];

    for (const source of this.sources) {
      for (const secret of source.load()) {
        if (seenValues.has(secret.value) || seenNames.has(secret.name)) continue;
        seenValues.add(secret.value);
        seenNames.add(secret.name);
        secrets.push(secret);
      }
    }

    return secrets;
  }
}
