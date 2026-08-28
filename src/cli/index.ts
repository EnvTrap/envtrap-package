#!/usr/bin/env node
// src/cli/index.ts
// CLI entry point — Commander.js wiring only.
//
// This file is intentionally minimal. All run logic lives in runner.ts.

import { Command } from 'commander';
import { loadConfig } from '../config/ConfigLoader.js';
import { runCommand, type RunOptions } from './runner.js';

import { getVersion } from '../config/Version.js';

const program = new Command();
const version = getVersion();

program
  .name('envtrap')
  .description(`envtrap v${version} — Zero-Configuration Runtime Secret Leak Detector`)
  .version(version);

program
  .command('check')
  .description('Validate the envtrap.json configuration file')
  .action(() => {
    const { errors, loaded } = loadConfig(process.cwd());
    if (!loaded) {
      console.log('No envtrap.json found. Using default settings.');
      process.exit(0);
    }
    if (errors.length > 0) {
      console.error('Configuration Validation Failed:');
      for (const err of errors) {
        console.error(`  - [${err.path}] ${err.message}`);
      }
      process.exit(1);
    }
    console.log('Configuration is valid.');
    process.exit(0);
  });

program
  .command('run <command> [args...]')
  .description('Run a command under envtrap monitoring')
  .option('-e, --env-file <path>', 'Path to a custom .env file', '.env')
  .option('-v, --verbose',          'Enable verbose proxy/hook logging', false)
  .option('--no-mitm',              'Disable HTTPS MITM proxy')
  .option('--quiet',                'Suppress banner and leak alerts (show summary only)', false)
  .option('--log-file <path>',      'Path to write structured JSONL events')
  .action(async (command: string, args: string[], options: RunOptions) => {
    await runCommand(command, args, options);
  });

program.parse(process.argv);
