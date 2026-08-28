// src/cli/StdioHandler.ts
// Handles real-time chunk reading, scanning, redacting, and protocol routing for child stdio.
//
// Single responsibility: stdio stream intercept processing.

import type { IScanner } from '../ports/IScanner.js';
import type { OutputRedactor } from '../domain/OutputRedactor.js';
import { HookMessageParser } from './HookMessageParser.js';
import type { Secret } from '../types.js';

export class StdioHandler {
  private readonly parser = new HookMessageParser();
  private stderrRemainder = '';

  constructor(
    private readonly scanner: IScanner,
    private readonly redactor: OutputRedactor,
    private readonly secrets: readonly Secret[],
    private readonly warnReporter: (m: string) => void,
  ) {}

  handleStdout(chunk: Buffer, onBlock: () => void): void {
    const raw = chunk.toString('utf-8');
    const result = this.scanner.scan(raw, 'stdout');
    const redacted = this.redactor.redact(raw);
    process.stdout.write(redacted);

    if (result.blocked) {
      onBlock();
    }
  }

  handleStderr(chunk: Buffer, onBlock: () => void): void {
    const text = this.stderrRemainder + chunk.toString('utf-8');
    const lines = text.split('\n');
    this.stderrRemainder = lines.pop() ?? '';

    for (const line of lines) {
      if (this.handleStderrLine(line, onBlock)) return;
    }
  }

  handleStderrEnd(onBlock: () => void): void {
    if (this.stderrRemainder) {
      this.handleStderrLine(this.stderrRemainder, onBlock);
    }
  }

  private handleStderrLine(line: string, onBlock: () => void): boolean {
    const parsed = this.parser.parse(line);

    if (parsed.type === 'child_process_leak') {
      const found = this.secrets.find((s) => s.name === parsed.secretName);
      if (found) {
        const result = this.scanner.checkChildEnv({ [found.name]: found.value });
        if (result.blocked) {
          onBlock();
          return true;
        }
      }
      return false;
    }

    if (parsed.type === 'dns_leak') {
      const result = this.scanner.scan(parsed.detail ?? '', 'dns');
      if (result.blocked) {
        onBlock();
        return true;
      }
      return false;
    }

    if (parsed.type === 'dns_warning') {
      this.warnReporter(`Potential DNS tunneling (high entropy): ${parsed.detail}`);
      return false;
    }

    // Regular stderr line
    const result = this.scanner.scan(line, 'stderr');
    const redacted = this.redactor.redact(line);
    process.stderr.write(redacted + '\n');

    if (result.blocked) {
      onBlock();
      return true;
    }
    return false;
  }
}
