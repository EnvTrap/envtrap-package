// src/mitm/UpstreamConnector.ts
// Establishes a secure connection to the actual upstream server.
//
// Single responsibility: upstream TLS connection establishment and backpressure/piping.

import * as tls from 'tls';
import type { IScanner } from '../ports/IScanner.js';

export class UpstreamConnector {
  constructor(
    private readonly scanner: IScanner,
    private readonly reporter: { warn(m: string): void; info(m: string): void },
    private readonly isAllowed: boolean,
    private readonly mode: string,
    private readonly verbose: boolean,
  ) {}

  connect(
    hostname: string,
    port: number,
    downstream: tls.TLSSocket,
    onDestroy: () => void,
  ): tls.TLSSocket {
    const rejectUnauthorized = process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0';

    const upstream = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized },
      () => {
        if (this.verbose) {
          this.reporter.info(`Upstream TLS connected: ${hostname}:${port}`);
        }
      },
    );

    upstream.on('data', (chunk: Buffer) => {
      if (!this.isAllowed && this.mode !== 'off') {
        const blocked = this.scanner.scan(chunk.toString('utf-8'), 'network').blocked;
        if (blocked) {
          this.safeDestroy(downstream);
          this.safeDestroy(upstream);
          onDestroy();
          return;
        }
      }
      if (!downstream.destroyed) {
        downstream.write(chunk);
      }
    });

    upstream.on('end', () => {
      this.safeDestroy(downstream);
      onDestroy();
    });

    upstream.on('error', (err) => {
      this.reporter.warn(`Upstream error for ${hostname}: ${err.message}`);
      if (!downstream.destroyed) {
        try {
          downstream.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway');
        } catch { /* ignore */ }
        this.safeDestroy(downstream);
      }
      this.safeDestroy(upstream);
      onDestroy();
    });

    return upstream;
  }

  private safeDestroy(socket: tls.TLSSocket | null | undefined): void {
    if (socket && !socket.destroyed) {
      try { socket.destroy(); } catch { /* ignore */ }
    }
  }
}
