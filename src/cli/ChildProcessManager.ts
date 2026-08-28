// src/cli/ChildProcessManager.ts
// Handles spawning the child process and piping its stdio through handlers.
//
// Single responsibility: child process spawning and stdio stream attachment.

import { spawn, type ChildProcess } from 'child_process';
import type { StdioHandler } from './StdioHandler.js';

export class ChildProcessManager {
  private child: ChildProcess | null = null;
  private forceExit = false;

  constructor(
    private readonly command: string,
    private readonly args: string[],
    private readonly env: NodeJS.ProcessEnv,
    private readonly handler: StdioHandler,
  ) {}

  spawn(): ChildProcess {
    this.child = spawn(this.command, this.args, {
      env: this.env,
      stdio: ['inherit', 'pipe', 'pipe'],
    });

    const onBlock = () => {
      this.forceExit = true;
      this.child?.kill('SIGTERM');
    };

    this.child.stdout?.on('data', (chunk: Buffer) => {
      this.handler.handleStdout(chunk, onBlock);
    });

    this.child.stderr?.on('data', (chunk: Buffer) => {
      this.handler.handleStderr(chunk, onBlock);
    });

    this.child.stderr?.on('end', () => {
      this.handler.handleStderrEnd(onBlock);
    });

    return this.child;
  }

  isForceExited(): boolean {
    return this.forceExit;
  }
}
