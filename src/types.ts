// src/types.ts
// Canonical shared types for envtrap.

/** Human-readable channel name. */
export type ChannelName = 'stdout' | 'stderr' | 'network' | 'child_process' | 'dns';

/** A secret loaded from process.env or a .env file. */
export interface Secret {
  readonly name: string;
  readonly value: string;
  readonly source: 'env' | 'file';
}

/** A detected leak — a secret found in a monitored channel. */
export interface LeakEvent {
  readonly secret: Secret;
  readonly channel: ChannelName;
  readonly context: string;
  readonly timestamp: number;
}

/** Result of scanning a content chunk. */
export interface ScanResult {
  readonly leaked: boolean;
  readonly blocked: boolean;
}

/** Generated domain TLS credentials (PEM strings). */
export interface DomainCreds {
  readonly keyPem: string;
  readonly certPem: string;
}

/** Root CA materials kept in memory. */
export interface CaMaterials {
  readonly certPem: string;
  readonly certPath: string;
}
