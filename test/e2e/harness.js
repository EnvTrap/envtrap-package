// test/e2e/harness.js
const { spawn } = require('node:child_process');
const path = require('node:path');

const CLI_PATH = path.resolve(__dirname, '../../dist/cli/index.js');
const HOOKS_PATH = path.resolve(__dirname, '../../dist/hooks/hooks.mjs');

function runCli(args = [], customEnv = {}, cwd = process.cwd()) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd,
      env: { ...process.env, ...customEnv },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', reject);

    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

function runWithImport(scriptPath, customEnv = {}, cwd = process.cwd()) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [`--import=${HOOKS_PATH}`, scriptPath], {
      cwd,
      env: { ...process.env, ...customEnv },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', reject);

    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

module.exports = {
  CLI_PATH,
  HOOKS_PATH,
  runCli,
  runWithImport
};
