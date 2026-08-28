// src/reporting/ReportWriter.ts
// Writes the structured .envtrap-report.json file after a run ends.
//
// Separated from TerminalReporter so JSON serialization logic lives in
// one clear place and can be tested without terminal side effects.

import * as fs from 'fs';
import * as path from 'path';
import { getSha256 } from '../detection/fingerprint.js';
import type { LeakEvent } from '../types.js';

export class ReportWriter {
  private readonly outputDir: string;

  constructor(outputDir: string) {
    this.outputDir = outputDir;
  }

  /**
   * Serializes all events to .envtrap-report.json in the output directory.
   * Secret values are never written — only SHA-256 digests.
   */
  write(events: LeakEvent[]): void {
    const reportPath = path.resolve(this.outputDir, '.envtrap-report.json');

    const structured = events.map((ev) => ({
      secretName: ev.secret.name,
      source: ev.secret.source,
      channel: ev.channel,
      context: ev.context,
      sha256: getSha256(ev.secret.value),
      timestamp: ev.timestamp,
    }));

    fs.writeFileSync(reportPath, JSON.stringify(structured, null, 2), 'utf-8');
  }
}
