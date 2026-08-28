// src/cli/HookMessageParser.ts
// Parses runtime hook message protocols emitted to stderr by the child.
//
// Single responsibility: Protocol string parsing and classification.

export type HookMessageType = 'child_process_leak' | 'dns_leak' | 'dns_warning' | 'none';

export interface HookMessage {
  type: HookMessageType;
  secretName?: string;
  detail?: string;
}

export class HookMessageParser {
  parse(line: string): HookMessage {
    if (line.includes('[envtrap] Child process leak:')) {
      const match = /secret "([^"]+)" passed to: (.+)/.exec(line);
      if (match) {
        return {
          type: 'child_process_leak',
          secretName: match[1],
          detail: match[2],
        };
      }
    }

    if (line.includes('[envtrap] DNS leak:')) {
      const match = /secret "([^"]+)" found in lookup of: (.+)/.exec(line);
      if (match) {
        return {
          type: 'dns_leak',
          secretName: match[1],
          detail: match[2],
        };
      }
    }

    if (line.includes('[envtrap] DNS warning:')) {
      const match = /high-entropy lookup detected: (.+)/.exec(line);
      if (match) {
        return {
          type: 'dns_warning',
          detail: match[1],
        };
      }
    }

    return { type: 'none' };
  }
}
