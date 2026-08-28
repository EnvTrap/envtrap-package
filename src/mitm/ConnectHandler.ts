// src/mitm/ConnectHandler.ts
// Handles the HTTP CONNECT tunneling event and boots a loopback TLS intercept server.
//
// Single responsibility: CONNECT tunneling orchestration, TLS handshake.

import * as http from 'http';
import * as net from 'net';
import * as tls from 'tls';
import type { IScanner } from '../ports/IScanner.js';
import type { CertificateAuthority } from './CertificateAuthority.js';
import { TlsInterceptor } from './TlsInterceptor.js';

export class ConnectHandler {
  constructor(
    private readonly ca: CertificateAuthority,
    private readonly scanner: IScanner,
    private readonly reporter: { warn(m: string): void; info(m: string): void },
    private readonly allowedDomains: Set<string>,
    private readonly mode: string,
    private readonly verbose: boolean,
  ) {}

  async handle(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
  ): Promise<void> {
    const targetHost = req.url ?? '';
    const [hostname, portStr] = targetHost.split(':');
    const upstreamPort = parseInt(portStr ?? '443', 10);

    let creds: { keyPem: string; certPem: string };
    try {
      creds = this.ca.generateDomainCert(hostname);
    } catch (err) {
      this.reporter.warn(`Cert generation failed for ${hostname}: ${(err as Error).message}`);
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      this.safeDestroy(clientSocket);
      return;
    }

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const tlsServer = tls.createServer({
      SNICallback: (_sni: string, cb: (err: Error | null, ctx?: tls.SecureContext) => void) => {
        cb(null, tls.createSecureContext({ key: creds.keyPem, cert: creds.certPem }));
      },
    });

    tlsServer.on('secureConnection', (tlsSocket: tls.TLSSocket) => {
      const interceptor = new TlsInterceptor(
        this.scanner,
        this.reporter,
        this.allowedDomains.has(hostname),
        this.mode,
        this.verbose,
      );
      interceptor.intercept(tlsSocket, hostname, upstreamPort);
    });

    tlsServer.emit('connection', clientSocket);

    if (head.length > 0) {
      clientSocket.emit('data', head);
    }
  }

  private safeDestroy(socket: net.Socket): void {
    if (socket && !socket.destroyed) {
      try { socket.destroy(); } catch { /* ignore */ }
    }
  }
}
