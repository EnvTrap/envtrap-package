// src/ports/ISecretSource.ts
// Secret-source port — the contract for anything that can supply secrets.
// EnvSecretSource, DotEnvSecretSource, and any future sources implement this.

import type { Secret } from '../types.js';

export interface ISecretSource {
  /** Load and return all secret candidates from this source. */
  load(): Secret[];
}
