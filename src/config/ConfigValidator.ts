// src/config/ConfigValidator.ts
// Validates a raw unknown JSON object against the envtrap config schema.
// Single responsibility: validation only — no loading, no merging.

import type {
  ChannelConfig,
  ChannelMode,
  ConfigError,
} from './ConfigTypes.js';

const VALID_MODES: readonly ChannelMode[] = ['block', 'warn', 'off'];
const CHANNEL_KEYS: readonly (keyof ChannelConfig)[] = [
  'stdout', 'stderr', 'network', 'child_process', 'dns',
];

export class ConfigValidator {
  validate(raw: unknown): ConfigError[] {
    if (!this.isPlainObject(raw)) {
      return [{ path: '$', message: 'Root config must be a JSON object' }];
    }
    const obj = raw as Record<string, unknown>;
    return [
      ...this.validateChannels(obj),
      ...this.validateExclusions(obj),
      ...this.validateEntropy(obj),
      ...this.validateScalars(obj),
    ];
  }

  private isPlainObject(v: unknown): v is Record<string, unknown> {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
  }

  private hasOwn(o: object, p: string): boolean {
    return Object.prototype.hasOwnProperty.call(o, p);
  }

  private validateChannels(obj: Record<string, unknown>): ConfigError[] {
    if (!this.hasOwn(obj, 'channels')) return [];
    if (!this.isPlainObject(obj['channels'])) {
      return [{ path: '$.channels', message: 'Must be an object' }];
    }
    const ch = obj['channels'] as Record<string, unknown>;
    const errors: ConfigError[] = [];
    for (const key of Object.keys(ch)) {
      if (!CHANNEL_KEYS.includes(key as keyof ChannelConfig)) {
        errors.push({ path: `$.channels.${key}`, message: `Unknown channel key "${key}"` });
        continue;
      }
      if (!VALID_MODES.includes(ch[key] as ChannelMode)) {
        errors.push({ path: `$.channels.${key}`, message: `Invalid mode "${ch[key]}"` });
      }
    }
    return errors;
  }

  private validateExclusions(obj: Record<string, unknown>): ConfigError[] {
    if (!this.hasOwn(obj, 'exclusions')) return [];
    if (!this.isPlainObject(obj['exclusions'])) {
      return [{ path: '$.exclusions', message: 'Must be an object' }];
    }
    const ex = obj['exclusions'] as Record<string, unknown>;
    const errors: ConfigError[] = [];
    if (this.hasOwn(ex, 'domains') && !Array.isArray(ex['domains'])) {
      errors.push({ path: '$.exclusions.domains', message: 'Must be an array of strings' });
    }
    if (this.hasOwn(ex, 'paths') && !Array.isArray(ex['paths'])) {
      errors.push({ path: '$.exclusions.paths', message: 'Must be an array of strings' });
    }
    return errors;
  }

  private validateEntropy(obj: Record<string, unknown>): ConfigError[] {
    if (!this.hasOwn(obj, 'entropy')) return [];
    if (!this.isPlainObject(obj['entropy'])) {
      return [{ path: '$.entropy', message: 'Must be an object' }];
    }
    const en = obj['entropy'] as Record<string, unknown>;
    const errors: ConfigError[] = [];
    if (this.hasOwn(en, 'threshold') && typeof en['threshold'] !== 'number') {
      errors.push({ path: '$.entropy.threshold', message: 'Must be a number' });
    }
    if (this.hasOwn(en, 'minLength') && typeof en['minLength'] !== 'number') {
      errors.push({ path: '$.entropy.minLength', message: 'Must be a number' });
    }
    return errors;
  }

  private validateScalars(obj: Record<string, unknown>): ConfigError[] {
    const errors: ConfigError[] = [];
    if (this.hasOwn(obj, 'quiet') && typeof obj['quiet'] !== 'boolean') {
      errors.push({ path: '$.quiet', message: 'Must be a boolean' });
    }
    if (this.hasOwn(obj, 'logFile') && obj['logFile'] !== null && typeof obj['logFile'] !== 'string') {
      errors.push({ path: '$.logFile', message: 'Must be a string or null' });
    }
    return errors;
  }
}
