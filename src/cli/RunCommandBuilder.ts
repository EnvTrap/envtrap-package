// src/cli/RunCommandBuilder.ts
// Factory/Builder class to wire up all SOLID dependencies for the RunCommand execution.
//
// Single responsibility: Assembly and wiring of dependencies.

import * as path from 'path';
import * as fs from 'fs';
import type { RunOptions } from './runner.js';
import { RunCommand } from './RunCommand.js';
import { loadConfig } from '../config/ConfigLoader.js';
import { EnvSecretSource } from '../secrets/EnvSecretSource.js';
import { DotEnvSecretSource } from '../secrets/DotEnvSecretSource.js';
import { SecretSourceComposer } from '../secrets/SecretSourceComposer.js';
import { SecretMatcher } from '../domain/SecretMatcher.js';
import { Scanner } from '../scanner/Scanner.js';
import { BannerPrinter } from '../reporting/BannerPrinter.js';
import { LeakAlertPrinter } from '../reporting/LeakAlertPrinter.js';
import { FileEventLogger } from '../reporting/FileEventLogger.js';
import { CompositeReporter } from '../reporting/CompositeReporter.js';
import { RunSummaryPrinter } from '../reporting/RunSummaryPrinter.js';
import { ReportWriter } from '../reporting/ReportWriter.js';

export class RunCommandBuilder {
  build(options: RunOptions): RunCommand {
    const { config, errors: configErrors, loaded: configLoaded } = loadConfig(process.cwd());

    const quiet   = options.quiet || config.quiet;
    const logFile = options.logFile ?? config.logFile;

    const alertPrinter = new LeakAlertPrinter(quiet);
    const fileLogger   = new FileEventLogger(logFile ? path.resolve(process.cwd(), logFile) : null);
    const reporter     = new CompositeReporter([alertPrinter, fileLogger]);

    const banner  = new BannerPrinter(quiet);
    const summary = new RunSummaryPrinter();
    const report  = new ReportWriter(process.cwd());

    const warnReporter = (msg: string) => {
      if (!quiet) {
        console.error(`[envtrap] warning: ${msg}`);
      }
    };

    if (configLoaded && configErrors.length > 0) {
      warnReporter('Configuration file validation warnings/errors:');
      for (const err of configErrors) {
        warnReporter(`  - [${err.path}] ${err.message}`);
      }
    }

    const envSource = new EnvSecretSource(config.entropy);
    const dotEnvSource = new DotEnvSecretSource(options.envFile, config.entropy);
    const composer = new SecretSourceComposer([envSource, dotEnvSource]);
    const secrets = composer.load();

    const matcher = new SecretMatcher(secrets, config.entropy);
    const scanner = new Scanner(matcher, config, reporter);

    if (!quiet) {
      this.printDiagnostics(configLoaded, config, secrets, options.verbose, warnReporter);
    }

    return new RunCommand(
      config,
      secrets,
      options,
      scanner,
      banner,
      summary,
      report,
      warnReporter,
      this.resolveHooksPath,
    );
  }

  private printDiagnostics(
    configLoaded: boolean,
    config: any,
    secrets: any[],
    verbose: boolean,
    warn: (m: string) => void,
  ): void {
    warn(`Configuration: ${configLoaded ? 'envtrap.json' : 'default settings'}`);
    warn('Active channels:');
    for (const [ch, mode] of Object.entries(config.channels)) {
      warn(`  - ${ch}: [${(mode as string).toUpperCase()}]`);
    }
    if (config.exclusions.domains.length > 0) {
      warn(`Bypassed domains: ${config.exclusions.domains.join(', ')}`);
    }
    if (verbose) {
      warn(`Loaded ${secrets.length} secrets from env/file sources`);
    }
  }

  private resolveHooksPath(): string {
    const distHooks = path.resolve(__dirname, '..', 'hooks', 'hooks.mjs');
    const srcHooks  = path.resolve(__dirname, '..', '..', 'src', 'hooks', 'hooks.mjs');

    if (fs.existsSync(distHooks)) return distHooks;
    if (fs.existsSync(srcHooks))  return srcHooks;

    throw new Error(
      `[envtrap] Cannot find hooks.mjs. Expected at:\n  ${distHooks}\n  ${srcHooks}`,
    );
  }
}
