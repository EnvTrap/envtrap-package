// src/mitm/HttpHandler.ts
// Handles plain HTTP request interception, scanning, and upstream forwarding.
//
// Single responsibility: intercept plain HTTP (non-TLS) traffic.

import * as http from 'http';
import type { IScanner } from '../ports/IScanner.js';

export class HttpHandler {
  constructor(
    private readonly scanner: IScanner,
    private readonly reporter: { warn(m: string): void; info(m: string): void },
    private readonly allowedDomains: Set<string>,
    private readonly mode: string,
    private readonly verbose: boolean,
  ) {}

  handle(req: http.IncomingMessage, res: http.ServerResponse): void {
    const hostHeader = req.headers.host ?? '';
    const hostname   = hostHeader.split(':')[0];
    const isAllowed  = this.allowedDomains.has(hostname);

    if (this.verbose) {
      this.reporter.info(`HTTP intercept: ${req.method} ${req.url} (allowed: ${isAllowed})`);
    }

    const bodyChunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => bodyChunks.push(chunk));

    req.on('end', () => {
      let blocked = false;

      if (!isAllowed && this.mode !== 'off') {
        const body = Buffer.concat(bodyChunks).toString('utf-8');
        if (body) {
          blocked = this.scanner.scan(body, 'network').blocked || blocked;
        }
        blocked = this.scanner.scan(JSON.stringify(req.headers), 'network').blocked || blocked;
        blocked = this.scanner.scan(req.url ?? '', 'network').blocked || blocked;
      }

      if (blocked) {
        if (this.verbose) {
          this.reporter.warn('HTTP request blocked due to secret leak');
        }
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Blocked by envtrap');
        return;
      }

      const opts: http.RequestOptions = {
        host:    hostHeader,
        path:    req.url,
        method:  req.method,
        headers: req.headers,
      };

      const proxyReq = http.request(opts, (proxyRes) => {
        res.writeHead(proxyRes.statusCode ?? 200, proxyRes.headers);
        proxyRes.pipe(res);
      });

      proxyReq.on('error', (err) => {
        this.reporter.warn(`HTTP upstream error: ${err.message}`);
        res.writeHead(502);
        res.end('Bad Gateway');
      });

      proxyReq.write(Buffer.concat(bodyChunks));
      proxyReq.end();
    });
  }
}
