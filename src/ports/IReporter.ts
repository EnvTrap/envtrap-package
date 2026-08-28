// src/ports/IReporter.ts
// Reporter port — the contract that all reporter implementations must satisfy.
// Separates the concern of "detecting a leak" from "deciding what to do with it".

import type { LeakEvent } from '../types.js';

export interface IReporter {
  /** Called once per unique leak event. */
  report(event: LeakEvent): void;
}
