// src/cli/ChildEnvBuilder.ts
// Builds the environment variables object injected into the child process.
//
// Single responsibility: Environment injection construction.

import type { EnvtrapConfig } from '../config/ConfigTypes.js';
import type { Secret } from '../types.js';

export class ChildEnvBuilder {
  build(options: {
    mitmEnabled: boolean;
    proxyPort: number;
    caCertPath: string;
    config: EnvtrapConfig;
    secrets: readonly Secret[];
    hooksPath: string;
  }): NodeJS.ProcessEnv {
    const { mitmEnabled, proxyPort, caCertPath, config, secrets, hooksPath } = options;

    const secretsMap: Record<string, string> = {};
    for (const s of secrets) {
      secretsMap[s.name] = s.value;
    }

    const noProxyList = this.buildNoProxyList(config.exclusions.domains);

    return {
      ...process.env,
      ...(mitmEnabled && proxyPort > 0
        ? {
            HTTP_PROXY:  `http://127.0.0.1:${proxyPort}`,
            HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
            http_proxy:  `http://127.0.0.1:${proxyPort}`,
            https_proxy: `http://127.0.0.1:${proxyPort}`,
            NO_PROXY:    noProxyList,
            no_proxy:    noProxyList,
          }
        : {}),
      ...(mitmEnabled && caCertPath ? { NODE_EXTRA_CA_CERTS: caCertPath } : {}),
      NODE_OPTIONS:                    this.buildNodeOptions(hooksPath, process.env.NODE_OPTIONS),
      __ENVTRAP_SECRETS_MAP__:         JSON.stringify(secretsMap),
      __ENVTRAP_SECRET_NAMES__:        JSON.stringify(secrets.map((s) => s.name)),
      __ENVTRAP_CONFIG_MODES__:        JSON.stringify(config.channels),
      __ENVTRAP_PATH_EXCLUSIONS__:     JSON.stringify(config.exclusions.paths),
      __ENVTRAP_ENTROPY_THRESHOLD__:   String(config.entropy.threshold),
      __ENVTRAP_ENTROPY_MIN_LENGTH__:  String(config.entropy.minLength),
    };
  }

  private buildNoProxyList(domains: string[]): string {
    const defaults = ['localhost', '127.0.0.1', '::1', '0.0.0.0', '127.*'];
    const userNoProxy = (process.env.NO_PROXY ?? process.env.no_proxy ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return Array.from(new Set([...defaults, ...domains, ...userNoProxy])).join(',');
  }

  private buildNodeOptions(hooksPath: string, existing?: string): string {
    const flag = `--import ${hooksPath}`;
    if (!existing) return flag;
    if (existing.includes(hooksPath)) return existing;
    return `${existing} ${flag}`;
  }
}
