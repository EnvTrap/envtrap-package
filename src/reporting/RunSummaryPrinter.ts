// src/reporting/RunSummaryPrinter.ts
// Prints the end-of-run summary grouped by channel.
// Single responsibility: summary output only.

import chalk from 'chalk';
import type { LeakEvent } from '../types.js';

const CHANNEL_META: Record<LeakEvent['channel'], { label: string; color: chalk.Chalk }> = {
  stdout:        { label: 'STDOUT',     color: chalk.yellow  },
  stderr:        { label: 'STDERR',     color: chalk.red     },
  network:       { label: 'NETWORK',    color: chalk.magenta },
  child_process: { label: 'CHILD PROC', color: chalk.cyan    },
  dns:           { label: 'DNS',        color: chalk.blue    },
};

export class RunSummaryPrinter {
  print(events: readonly LeakEvent[]): void {
    console.error(chalk.bold.white('[envtrap] Run Summary'));
    events.length === 0 ? this.printClean() : this.printLeaks(events);
  }

  private printClean(): void {
    console.error(chalk.green('  No secret leaks detected. All clear.'));
  }

  private printLeaks(events: readonly LeakEvent[]): void {
    console.error(chalk.red.bold(`  ${events.length} leak event(s) detected!`));
    console.error('');
    for (const [channel, channelEvents] of this.groupByChannel(events)) {
      const meta = CHANNEL_META[channel];
      console.error(`  ${meta.color.bold(meta.label)}: ${channelEvents.length} leak(s)`);
      for (const name of this.uniqueNames(channelEvents)) {
        console.error(`       -> ${chalk.yellow(name)}`);
      }
    }
  }

  private groupByChannel(events: readonly LeakEvent[]): Map<LeakEvent['channel'], LeakEvent[]> {
    const map = new Map<LeakEvent['channel'], LeakEvent[]>();
    for (const ev of events) {
      const arr = map.get(ev.channel) ?? [];
      arr.push(ev);
      map.set(ev.channel, arr);
    }
    return map;
  }

  private uniqueNames(events: LeakEvent[]): string[] {
    return [...new Set(events.map((e) => e.secret.name))];
  }
}
