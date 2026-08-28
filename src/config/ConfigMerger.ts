// src/config/ConfigMerger.ts
// Deep-merges user config on top of defaults.
// Single responsibility: merging — no validation, no file I/O.

import {
  DEFAULT_CONFIG,
  VALID_MODES,
  type ChannelConfig,
  type ChannelMode,
  type EnvtrapConfig,
  type ExclusionsConfig,
  type EntropyConfig,
} from './ConfigTypes.js';

export class ConfigMerger {
  merge(user: unknown): EnvtrapConfig {
    if (typeof user !== 'object' || user === null) return { ...DEFAULT_CONFIG };
    const u = user as Record<string, unknown>;
    return {
      channels:   this.mergeChannels(u['channels']),
      exclusions: this.mergeExclusions(u['exclusions']),
      entropy:    this.mergeEntropy(u['entropy']),
      quiet:      typeof u['quiet'] === 'boolean' ? u['quiet'] : DEFAULT_CONFIG.quiet,
      logFile:    typeof u['logFile'] === 'string' ? u['logFile'] : DEFAULT_CONFIG.logFile,
    };
  }

  private mergeChannels(raw: unknown): ChannelConfig {
    const u = this.isObj(raw) ? raw as Partial<ChannelConfig> : {};
    const d = DEFAULT_CONFIG.channels;
    return {
      stdout:        this.validMode(u.stdout)        ?? d.stdout,
      stderr:        this.validMode(u.stderr)        ?? d.stderr,
      network:       this.validMode(u.network)       ?? d.network,
      child_process: this.validMode(u.child_process) ?? d.child_process,
      dns:           this.validMode(u.dns)           ?? d.dns,
    };
  }

  private mergeExclusions(raw: unknown): ExclusionsConfig {
    const u = this.isObj(raw) ? raw as Partial<ExclusionsConfig> : {};
    return {
      domains: this.stringArray(u.domains) ?? DEFAULT_CONFIG.exclusions.domains,
      paths:   this.stringArray(u.paths)   ?? DEFAULT_CONFIG.exclusions.paths,
    };
  }

  private mergeEntropy(raw: unknown): EntropyConfig {
    const u = this.isObj(raw) ? raw as Partial<EntropyConfig> : {};
    return {
      threshold: typeof u.threshold === 'number' ? u.threshold : DEFAULT_CONFIG.entropy.threshold,
      minLength: typeof u.minLength === 'number' ? u.minLength : DEFAULT_CONFIG.entropy.minLength,
    };
  }

  private validMode(v: unknown): ChannelMode | null {
    return VALID_MODES.includes(v as ChannelMode) ? v as ChannelMode : null;
  }

  private stringArray(v: unknown): string[] | null {
    if (!Array.isArray(v)) return null;
    return v.filter((x): x is string => typeof x === 'string');
  }

  private isObj(v: unknown): boolean {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
  }
}
