// src/reporting/ILeakReporter.ts
// Segregated interface: receives exactly one leak event.
// Consumers only need this — not a full reporter with summary/banner methods.

import type { LeakEvent } from '../types.js';

export interface ILeakReporter {
  report(event: LeakEvent): void;
}
