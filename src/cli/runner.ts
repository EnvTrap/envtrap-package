// src/cli/runner.ts
// Legacy delegate for backward compatibility.
//
// Single responsibility: Delegate execution to the SOLID RunCommandBuilder.

import { RunCommandBuilder } from './RunCommandBuilder.js';

export interface RunOptions {
  envFile: string;
  verbose: boolean;
  mitm: boolean;
  quiet: boolean;
  logFile?: string;
}

export async function runCommand(
  command: string,
  args: string[],
  options: RunOptions,
): Promise<void> {
  const runner = new RunCommandBuilder().build(options);
  await runner.execute(command, args);
}
