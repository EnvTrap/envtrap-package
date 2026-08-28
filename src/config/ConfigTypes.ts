// src/config/ConfigTypes.ts
// All configuration types and the default config value.
// No file I/O, no logic — types and constants only.

export type ChannelMode = 'block' | 'warn' | 'off';

export interface ChannelConfig {
  stdout: ChannelMode;
  stderr: ChannelMode;
  network: ChannelMode;
  child_process: ChannelMode;
  dns: ChannelMode;
}

export interface ExclusionsConfig {
  domains: string[];
  paths: string[];
}

export interface EntropyConfig {
  threshold: number;
  minLength: number;
}

export interface EnvtrapConfig {
  channels: ChannelConfig;
  exclusions: ExclusionsConfig;
  entropy: EntropyConfig;
  quiet: boolean;
  logFile: string | null;
}

export interface ConfigError {
  path: string;
  message: string;
}

export interface LoadConfigResult {
  config: EnvtrapConfig;
  errors: ConfigError[];
  loaded: boolean;
}

// Exported so ConfigMerger and ConfigValidator can use it without circular imports.
export const VALID_MODES: readonly ChannelMode[] = ['block', 'warn', 'off'];

export const DEFAULT_CONFIG: EnvtrapConfig = {
  channels: {
    stdout: 'warn',
    stderr: 'warn',
    network: 'block',
    child_process: 'warn',
    dns: 'block',
  },
  exclusions: { domains: [], paths: [] },
  entropy:    { threshold: 3.5, minLength: 12 },
  quiet:      false,
  logFile:    null,
};
