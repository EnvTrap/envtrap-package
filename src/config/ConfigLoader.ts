// src/config/ConfigLoader.ts
// Reads envtrap.json from disk and delegates to ConfigValidator + ConfigMerger.
// Single responsibility: file I/O + orchestration. No validation logic here.

import * as fs from 'fs';
import * as path from 'path';
import { ConfigValidator } from './ConfigValidator.js';
import { ConfigMerger } from './ConfigMerger.js';
import { DEFAULT_CONFIG, type LoadConfigResult } from './ConfigTypes.js';

export class ConfigLoader {
  private readonly validator = new ConfigValidator();
  private readonly merger    = new ConfigMerger();

  load(cwd: string): LoadConfigResult {
    const configPath = path.resolve(cwd, 'envtrap.json');
    if (!fs.existsSync(configPath)) {
      return { config: { ...DEFAULT_CONFIG }, errors: [], loaded: false };
    }
    return this.parse(configPath);
  }

  private parse(configPath: string): LoadConfigResult {
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    } catch (err) {
      return {
        config: { ...DEFAULT_CONFIG },
        errors: [{ path: '$', message: `Failed to parse JSON: ${(err as Error).message}` }],
        loaded: true,
      };
    }
    return {
      config: this.merger.merge(raw),
      errors: this.validator.validate(raw),
      loaded: true,
    };
  }
}

// Convenience function for callers that don't need the class.
export function loadConfig(cwd: string): LoadConfigResult {
  return new ConfigLoader().load(cwd);
}
