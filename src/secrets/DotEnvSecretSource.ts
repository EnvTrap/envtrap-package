// src/secrets/DotEnvSecretSource.ts
// Loads secret candidates from a .env file on disk.
// Single responsibility: one source, one medium.

import * as dotenv from 'dotenv';
import * as fs from 'fs';
import { looksLikeSecret } from '../detection/fingerprint.js';
import type { ISecretSource } from '../ports/ISecretSource.js';
import type { Secret } from '../types.js';
import type { EntropyConfig } from '../config/ConfigTypes.js';

export class DotEnvSecretSource implements ISecretSource {
  constructor(
    private readonly filePath: string,
    private readonly entropy: EntropyConfig,
  ) {}

  load(): Secret[] {
    if (!fs.existsSync(this.filePath)) return [];
    const parsed = dotenv.parse(fs.readFileSync(this.filePath));
    return Object.entries(parsed)
      .filter(([, value]) => looksLikeSecret(value, this.entropy.minLength, this.entropy.threshold))
      .map(([name, value]) => ({ name, value, source: 'file' as const }));
  }
}
