// src/ports/IScanner.ts
// Scanning port — the contract that all scanner implementations must satisfy.
// High-level modules (MITM proxy, stdio handlers) depend on this, never on
// the concrete Scanner class directly.

import type { ChannelName, LeakEvent, ScanResult } from '../types.js';

export interface IScanner {
  /** Scan arbitrary content for secrets in the given channel. */
  scan(content: string, channel: ChannelName): ScanResult;

  /** Check a spawned-process env object for secret leakage. */
  checkChildEnv(env: Record<string, string | undefined>): ScanResult;

  /** Return all leak events accumulated during this run. */
  getEvents(): readonly LeakEvent[];
}
