// src/scanner/Scanner.ts
// Coordinates secret detection for a single monitoring session.
//
// Design:
//   - Scanner depends on IReporter (DIP) — never on TerminalReporter directly
//   - SecretMatcher finds matches; EventLog accumulates and deduplicates them
//   - Channel mode (block/warn/off) is read from EnvtrapConfig at scan time
//   - ≤2 meaningful collaborator fields on Scanner itself

import { ContentClamp } from '../domain/ContentClamp.js';
import { DedupCache } from '../domain/DedupCache.js';
import { SecretMatcher } from '../domain/SecretMatcher.js';
import { extractContext } from '../detection/fingerprint.js';
import { formatNetworkContext } from '../detection/HttpParser.js';
import type { IScanner } from '../ports/IScanner.js';
import type { IReporter } from '../ports/IReporter.js';
import type { ChannelName, LeakEvent, ScanResult, Secret } from '../types.js';
import type { EnvtrapConfig } from '../config/ConfigTypes.js';

// ---------------------------------------------------------------------------
// EventLog — private collaborator class.
// Owns deduplication and reporter notification so Scanner stays slim.
// ---------------------------------------------------------------------------

class EventLog {
  private readonly events: LeakEvent[] = [];
  private readonly dedup = new DedupCache();

  constructor(private readonly reporter: IReporter) {}

  record(secret: Secret, channel: ChannelName, content: string): void {
    const key = `${secret.name}:${channel}`;
    if (this.dedup.isDuplicate(key)) return;
    this.dedup.record(key);
    const event = buildEvent(secret, channel, content);
    this.events.push(event);
    this.reporter.report(event);
  }

  getAll(): readonly LeakEvent[] { return this.events; }
}

function buildEvent(secret: Secret, channel: ChannelName, content: string): LeakEvent {
  return {
    secret,
    channel,
    context: channel === 'network'
      ? formatNetworkContext(content, secret.value)
      : extractContext(content, secret.value),
    timestamp: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export class Scanner implements IScanner {
  private readonly clamp = new ContentClamp();
  private readonly log: EventLog;

  constructor(
    private readonly matcher: SecretMatcher,
    private readonly config: EnvtrapConfig,
    reporter: IReporter,
  ) {
    this.log = new EventLog(reporter);
  }

  scan(rawContent: string, channel: ChannelName): ScanResult {
    const mode = this.config.channels[channel] ?? 'warn';
    if (mode === 'off' || !rawContent) return none();

    const content = this.clamp.clamp(rawContent);
    const found   = this.matcher.findIn(content);
    if (found.length === 0) return none();

    for (const secret of found) this.log.record(secret, channel, content);
    return { leaked: true, blocked: mode === 'block' };
  }

  checkChildEnv(env: Record<string, string | undefined>): ScanResult {
    const mode = this.config.channels.child_process ?? 'warn';
    if (mode === 'off') return none();

    const matches = this.matcher.findMatchingKeys(env);
    if (matches.length === 0) return none();

    for (const secret of matches) {
      this.log.record(secret, 'child_process', `env key "${secret.name}" passed to child process`);
    }
    return { leaked: true, blocked: mode === 'block' };
  }

  getEvents(): readonly LeakEvent[] { return this.log.getAll(); }
}

function none(): ScanResult { return { leaked: false, blocked: false }; }
