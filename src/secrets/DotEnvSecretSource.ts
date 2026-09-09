// src/secrets/DotEnvSecretSource.ts
// Loads secret candidates from a .env file on disk.
// Single responsibility: one source, one medium.

import * as dotenv from 'dotenv';
import * as fs from 'fs';
import type { ISecretSource } from '../ports/ISecretSource.js';
import type { Secret } from '../types.js';
import type { EntropyConfig } from '../config/ConfigTypes.js';

export class DotEnvSecretSource implements ISecretSource {
  constructor(
    private readonly filePath: string,
    _entropy?: EntropyConfig,
  ) {}

  load(): Secret[] {
    if (!fs.existsSync(this.filePath)) return [];
    const parsed = dotenv.parse(fs.readFileSync(this.filePath));
    return Object.entries(parsed)
      .filter(([, value]) => typeof value === 'string' && value.trim().length >= 4)
      .map(([name, value]) => ({ name, value, source: 'file' as const }));
  }
}
