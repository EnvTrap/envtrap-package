// src/reporting/LeakAlertPrinter.ts
// Prints a single leak event alert to stderr with ANSI colours.
// Single responsibility: format and print one leak alert — nothing else.

import chalk from 'chalk';
import { getSha256 } from '../detection/fingerprint.js';
import type { ILeakReporter } from './ILeakReporter.js';
import type { LeakEvent } from '../types.js';

const CHANNEL_META: Record<LeakEvent['channel'], { label: string; color: chalk.Chalk }> = {
  stdout:        { label: 'STDOUT',     color: chalk.yellow  },
  stderr:        { label: 'STDERR',     color: chalk.red     },
  network:       { label: 'NETWORK',    color: chalk.magenta },
  child_process: { label: 'CHILD PROC', color: chalk.cyan    },
  dns:           { label: 'DNS',        color: chalk.blue    },
};

export class LeakAlertPrinter implements ILeakReporter {
  constructor(private readonly quiet: boolean = false) {}

  report(event: LeakEvent): void {
    if (this.quiet) return;
    const meta = CHANNEL_META[event.channel];
    const ts   = new Date(event.timestamp).toISOString();
    console.error(chalk.red.bold(`[envtrap] SECRET LEAK DETECTED`) + '  ' + chalk.gray(ts));
    console.error(`  ${chalk.gray('Secret:')}  ${meta.color.bold(event.secret.name)}  ${chalk.gray(`(source: ${event.secret.source})`)}`);
    console.error(`  ${chalk.gray('Value:')}   ${chalk.red(this.mask(event.secret.value))}`);
    console.error(`  ${chalk.gray('Channel:')} ${meta.color(meta.label)}`);
    this.printContext(event);
  }

  private mask(value: string): string {
    return `[SHA256:${getSha256(value).slice(0, 12)}...]`;
  }

  private printContext(event: LeakEvent): void {
    if (!event.context) return;
    console.error(`  ${chalk.gray('Context:')}`);
    if (event.channel === 'network') {
      for (const line of event.context.split('\n')) console.error(`    ${line}`);
      return;
    }
    console.error(`    ${chalk.gray(event.context.slice(0, 120))}`);
  }
}
