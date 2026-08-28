// src/reporting/CompositeReporter.ts
// Fans out a single leak event to N ILeakReporter implementations.
// Single responsibility: delegation — no formatting, no I/O.
// Implements IReporter (the scanner's port) and ILeakReporter.

import type { IReporter } from '../ports/IReporter.js';
import type { ILeakReporter } from './ILeakReporter.js';
import type { LeakEvent } from '../types.js';

export class CompositeReporter implements IReporter, ILeakReporter {
  constructor(private readonly reporters: readonly ILeakReporter[]) {}

  report(event: LeakEvent): void {
    for (const r of this.reporters) r.report(event);
  }
}
