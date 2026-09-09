import * as dotenv from 'dotenv';
import * as fs from 'fs';
import { looksLikeSecret } from '../detection/fingerprint.js';
import type { ISecretSource } from '../ports/ISecretSource.js';
import type { Secret } from '../types.js';
import type { EntropyConfig } from '../config/ConfigTypes.js';

// Common non-secret configuration keys that appear in .env files
const CONFIG_KEY_BLOCKLIST = new Set([
  'PORT', 'NODE_ENV', 'HOST', 'HOSTNAME', 'DEBUG', 'LOG_LEVEL', 'LOG_FORMAT',
  'APP_ENV', 'ENVIRONMENT', 'APP_PORT', 'SERVER_PORT', 'TIMEOUT',
  'CACHE_DRIVER', 'QUEUE_CONNECTION', 'MAIL_DRIVER', 'SESSION_DRIVER',
  'TZ', 'TIMEZONE', 'LOCALE', 'LANG', 'CHARSET', 'SSL', 'HTTPS',
  'CORS_ORIGIN', 'ALLOWED_ORIGINS', 'BASE_URL', 'PUBLIC_URL',
]);

// Common generic scalar values that should never be tracked as secrets
const VALUE_BLOCKLIST = new Set([
  'true', 'false', 'null', 'undefined', 'localhost', '0.0.0.0', '127.0.0.1', '::1',
  'production', 'development', 'staging', 'test', 'local',
  'json', 'text', 'html', 'info', 'warn', 'warning', 'error', 'debug', 'trace',
  'http', 'https', 'none', 'all',
]);

const CREDENTIAL_KEY_PATTERN = /(KEY|SECRET|PASSWORD|PASS|TOKEN|AUTH|CRED|PRIVATE|SIGN|CERT|HASH|SALT)/i;

export class DotEnvSecretSource implements ISecretSource {
  constructor(
    private readonly filePath: string,
    private readonly entropy?: EntropyConfig,
  ) {}

  load(): Secret[] {
    if (!fs.existsSync(this.filePath)) return [];
    const parsed = dotenv.parse(fs.readFileSync(this.filePath));
    return Object.entries(parsed)
      .filter(([name, value]) => this.isSecretCandidate(name, value))
      .map(([name, value]) => ({ name, value, source: 'file' as const }));
  }

  private isSecretCandidate(name: string, value: unknown): boolean {
    if (typeof value !== 'string') return false;
    const trimmed = value.trim();
    if (trimmed.length < 4) return false;

    // Never treat known non-secret keys or scalar values as secrets
    if (CONFIG_KEY_BLOCKLIST.has(name.toUpperCase())) return false;
    if (VALUE_BLOCKLIST.has(trimmed.toLowerCase())) return false;

    // Explicit credential variables retain without entropy gate (min length 4)
    if (CREDENTIAL_KEY_PATTERN.test(name)) return true;

    // Any other variable must satisfy looksLikeSecret heuristic if entropy config exists
    if (this.entropy) {
      return looksLikeSecret(trimmed, this.entropy.minLength, this.entropy.threshold);
    }

    return trimmed.length >= 12;
  }
}
