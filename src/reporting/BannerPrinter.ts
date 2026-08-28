// src/reporting/BannerPrinter.ts
// Prints the startup banner when envtrap begins monitoring.
// Single responsibility: the startup banner — nothing else.

import chalk from 'chalk';

export class BannerPrinter {
  constructor(private readonly quiet: boolean = false) {}

  print(command: string): void {
    if (this.quiet) return;
    console.error(chalk.red.bold('[envtrap]'));
    console.error(chalk.gray(`  Monitoring: ${chalk.white(command)}`));
    console.error(chalk.gray('  Channels:   stdout/stderr, HTTPS MITM, child_process, ESM hooks'));
  }
}
