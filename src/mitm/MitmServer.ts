// src/mitm/MitmServer.ts
// Bootstraps and runs the local MITM HTTP/HTTPS proxy server.
//
// Single responsibility: Proxy server startup, binding, and error orchestration.

import * as http from 'http';
import * as net from 'net';
import type { IScanner } from '../ports/IScanner.js';
import { CertificateAuthority } from './CertificateAuthority.js';
import type { EnvtrapConfig } from '../config/ConfigTypes.js';
import { HttpHandler } from './HttpHandler.js';
import { ConnectHandler } from './ConnectHandler.js';

export class MitmServer {
  private server: http.Server | null = null;

  constructor(
    private readonly ca: CertificateAuthority,
    private readonly scanner: IScanner,
    private readonly reporter: { warn(m: string): void; info(m: string): void },
    private readonly config: EnvtrapConfig,
    private readonly verbose: boolean,
  ) {}

  start(): Promise<number> {
    const allowedDomains = new Set(this.config.exclusions.domains);
    const mode = this.config.channels.network ?? 'block';

    const httpHandler = new HttpHandler(
      this.scanner,
      this.reporter,
      allowedDomains,
      mode,
      this.verbose,
    );

    const connectHandler = new ConnectHandler(
      this.ca,
      this.scanner,
      this.reporter,
      allowedDomains,
      mode,
      this.verbose,
    );

    return new Promise((resolve, reject) => {
      this.server = http.createServer();

      this.server.on('request', (req, res) => httpHandler.handle(req, res));

      this.server.on('connect', (req, socket, head) => {
        connectHandler.handle(req, socket as net.Socket, head).catch((err: Error) => {
          this.reporter.warn(`CONNECT tunnel handling error: ${err.message}`);
        });
      });

      this.server.on('error', reject);

      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server?.address();
        if (!addr || typeof addr === 'string') {
          reject(new Error('[envtrap/proxy] Failed to get bound port'));
          return;
        }
        resolve(addr.port);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}

// Keep the old export signature for simple compatibility if anyone calls it directly
export async function startProxy(
  scanner: IScanner,
  reporter: { warn(m: string): void; info(m: string): void },
  config: EnvtrapConfig,
  verbose = false,
): Promise<number> {
  const ca = new CertificateAuthority();
  ca.initCA();
  const server = new MitmServer(ca, scanner, reporter, config, verbose);
  return server.start();
}
