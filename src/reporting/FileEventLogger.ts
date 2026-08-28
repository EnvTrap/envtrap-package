// src/reporting/FileEventLogger.ts
// Appends each leak event to a JSONL log file.
// Single responsibility: JSONL file append — no console output.

import * as fs from 'fs';
import * as path from 'path';
import { getSha256 } from '../detection/fingerprint.js';
import type { ILeakReporter } from './ILeakReporter.js';
import type { LeakEvent } from '../types.js';

export class FileEventLogger implements ILeakReporter {
  constructor(private readonly logFilePath: string | null) {}

  report(event: LeakEvent): void {
    if (!this.logFilePath) return;
    try {
      this.ensureDir();
      fs.appendFileSync(this.logFilePath, this.serialize(event), 'utf-8');
    } catch {
      // File logging must never crash the monitored app.
    }
  }

  private ensureDir(): void {
    const dir = path.dirname(this.logFilePath!);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  private serialize(event: LeakEvent): string {
    return JSON.stringify({
      secretName: event.secret.name,
      source:     event.secret.source,
      channel:    event.channel,
      context:    event.context,
      sha256:     getSha256(event.secret.value),
      timestamp:  event.timestamp,
    }) + '\n';
  }
}
