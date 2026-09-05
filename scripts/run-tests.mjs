// scripts/run-tests.mjs
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const filterArg = process.argv[2] && !process.argv[2].startsWith('-') ? process.argv[2] : '';
const extraFlags = process.argv.slice(2).filter((arg) => arg.startsWith('-'));

const targetDir = filterArg ? path.resolve(root, 'test', filterArg) : path.resolve(root, 'test');

function getTestFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  let results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...getTestFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.test.js')) {
      results.push(full);
    }
  }
  return results;
}

const files = getTestFiles(targetDir);
if (files.length === 0) {
  console.error(`[envtrap] No test files found in ${targetDir}`);
  process.exit(1);
}

const args = ['--test', ...extraFlags, ...files];
const result = spawnSync(process.execPath, args, { stdio: 'inherit' });
process.exit(result.status ?? 0);
