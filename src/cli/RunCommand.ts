// src/cli/RunCommand.ts
// Top-level coordinator for the 'run' command lifecycle.
//
// Single responsibility: High-level orchestration. ≤ 50 lines.

import type { EnvtrapConfig } from '../config/ConfigTypes.js';
import type { Secret } from '../types.js';
import type { RunOptions } from './runner.js';
import type { Scanner } from '../scanner/Scanner.js';
import type { BannerPrinter } from '../reporting/BannerPrinter.js';
import type { RunSummaryPrinter } from '../reporting/RunSummaryPrinter.js';
import type { ReportWriter } from '../reporting/ReportWriter.js';
import { CertificateAuthority } from '../mitm/CertificateAuthority.js';
import { MitmServer } from '../mitm/MitmServer.js';
import { injectSystemCA, removeSystemCA } from '../mitm/SystemCaTrust.js';
import { OutputRedactor } from '../domain/OutputRedactor.js';
import { StdioHandler } from './StdioHandler.js';
import { ChildEnvBuilder } from './ChildEnvBuilder.js';
import { ChildProcessManager } from './ChildProcessManager.js';

export class RunCommand {
  private caCertPath = '';

  constructor(
    private readonly config: EnvtrapConfig,
    private readonly secrets: readonly Secret[],
    private readonly options: RunOptions,
    private readonly scanner: Scanner,
    private readonly banner: BannerPrinter,
    private readonly summary: RunSummaryPrinter,
    private readonly report: ReportWriter,
    private readonly warnReporter: (m: string) => void,
    private readonly resolveHooks: () => string,
  ) {}

  async execute(command: string, args: string[]): Promise<void> {
    this.banner.print(`${command} ${args.join(' ')}`);

    const mitmEnabled = this.options.mitm && this.config.channels.network !== 'off';
    const proxyPort = mitmEnabled ? await this.bootMitm() : 0;

    const envBuilder = new ChildEnvBuilder();
    const childEnv = envBuilder.build({
      mitmEnabled,
      proxyPort,
      caCertPath: this.caCertPath,
      config: this.config,
      secrets: this.secrets,
      hooksPath: this.resolveHooks(),
    });

    const redactor = new OutputRedactor(this.secrets);
    const stdio = new StdioHandler(this.scanner, redactor, this.secrets, this.warnReporter);
    const pm = new ChildProcessManager(command, args, childEnv, stdio);
    const child = pm.spawn();

    child.on('exit', (code, signal) => {
      this.handleExit(pm.isForceExited(), code, signal, mitmEnabled);
    });

    child.on('error', (err) => {
      this.warnReporter(`Failed to spawn process: ${err.message}`);
      process.exit(1);
    });
  }

  private async bootMitm(): Promise<number> {
    const ca = new CertificateAuthority();
    const materials = ca.initCA();
    this.caCertPath = materials.certPath;
    injectSystemCA(this.caCertPath, this.options.verbose);

    const server = new MitmServer(ca, this.scanner, {
      warn: (m) => this.warnReporter(m),
      info: () => {},
    }, this.config, this.options.verbose);

    return server.start();
  }

  private handleExit(forceExit: boolean, code: number | null, signal: string | null, mitm: boolean): void {
    const events = this.scanner.getEvents();
    this.summary.print(events);
    this.report.write([...events]);

    if (mitm && this.caCertPath) {
      removeSystemCA(this.caCertPath);
    }
    process.exit(forceExit ? 1 : (code ?? (signal ? 1 : 0)));
  }
}
