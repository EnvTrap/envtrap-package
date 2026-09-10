// src/mitm/TlsInterceptor.ts
// Decrypts, buffers, and scans the TLS client socket before sending upstream.
//
// Single responsibility: decrypted TLS stream interception, request scanning.

import * as tls from 'tls';
import type { IScanner } from '../ports/IScanner.js';
import { UpstreamConnector } from './UpstreamConnector.js';

const MAX_BUFFER_BYTES = 1_048_576; // 1 MB

export class TlsInterceptor {
  private totalBytes = 0;
  private readonly requestChunks: Buffer[] = [];
  private headersFlushed = false;
  private headerBuffer = Buffer.alloc(0);
  private lastOverlap = '';
  private upstreamSocket: tls.TLSSocket | null = null;

  constructor(
    private readonly scanner: IScanner,
    private readonly reporter: { warn(m: string): void; info(m: string): void },
    private readonly isAllowed: boolean,
    private readonly mode: string,
    private readonly verbose: boolean,
  ) {}

  intercept(
    tlsSocket: tls.TLSSocket,
    hostname: string,
    upstreamPort: number,
  ): void {
    const ensureUpstream = (): tls.TLSSocket => {
      if (!this.upstreamSocket) {
        const connector = new UpstreamConnector(
          this.scanner,
          this.reporter,
          this.isAllowed,
          this.mode,
          this.verbose,
        );
        this.upstreamSocket = connector.connect(
          hostname,
          upstreamPort,
          tlsSocket,
          () => {
            this.upstreamSocket = null;
          },
        );
      }
      return this.upstreamSocket;
    };

    tlsSocket.on('data', (chunk: Buffer) => {
      if (this.totalBytes < MAX_BUFFER_BYTES) {
        this.requestChunks.push(chunk);
        this.totalBytes += chunk.length;

        if (!this.isAllowed && this.mode !== 'off') {
          const chunkStr = chunk.toString('utf-8');
          const combined = this.lastOverlap + chunkStr;
          const blocked  = this.scanner.scan(combined, 'network').blocked;
          if (blocked) {
            if (this.verbose) {
              this.reporter.warn(`Network leak blocked: closing connection to ${hostname}`);
            }
            this.safeDestroy(tlsSocket);
            this.safeDestroy(this.upstreamSocket);
            return;
          }
          this.lastOverlap = combined.slice(-200);
        }
      }

      // Issue #6: Prevent early chunk leak by buffering initial HTTP headers
      // until \r\n\r\n delimiter is received and scanned before forwarding upstream.
      if (!this.headersFlushed) {
        this.headerBuffer = Buffer.concat([this.headerBuffer, chunk]);
        const headerIndex = this.headerBuffer.indexOf('\r\n\r\n');
        if (headerIndex !== -1 || this.isAllowed || this.mode === 'off' || this.headerBuffer.length >= 16384) {
          if (!this.isAllowed && this.mode !== 'off') {
            const headerStr = this.headerBuffer.slice(0, headerIndex !== -1 ? headerIndex + 4 : undefined).toString('utf-8');
            const blocked = this.scanner.scan(headerStr, 'network').blocked;
            if (blocked) {
              if (this.verbose) {
                this.reporter.warn(`Network leak blocked in HTTP headers: closing connection to ${hostname}`);
              }
              this.safeDestroy(tlsSocket);
              this.safeDestroy(this.upstreamSocket);
              return;
            }
          }

          this.headersFlushed = true;
          const up = ensureUpstream();
          if (up && !up.destroyed) {
            up.write(this.headerBuffer);
            this.headerBuffer = Buffer.alloc(0);
          }
        }
        return;
      }

      const up = ensureUpstream();
      if (up && !up.destroyed) {
        up.write(chunk);
      }
    });

    tlsSocket.on('end', () => {
      if (!this.isAllowed && this.mode !== 'off' && this.requestChunks.length > 0) {
        this.scanner.scan(Buffer.concat(this.requestChunks).toString('utf-8'), 'network');
      }
      if (!this.headersFlushed && this.headerBuffer.length > 0) {
        const up = ensureUpstream();
        if (up && !up.destroyed) {
          up.write(this.headerBuffer);
          this.headerBuffer = Buffer.alloc(0);
        }
      }
      this.safeDestroy(this.upstreamSocket);
    });

    tlsSocket.on('error', (err) => {
      if (this.verbose) {
        this.reporter.warn(`TLS client socket error on ${hostname}: ${err.message}`);
      }
      this.safeDestroy(this.upstreamSocket);
    });
  }

  private safeDestroy(socket: tls.TLSSocket | null): void {
    if (socket && !socket.destroyed) {
      try { socket.destroy(); } catch { /* ignore */ }
    }
  }
}
