// src/hooks/virtual/child-process.mjs
// Virtual module served as 'envtrap:child_process' for ESM imports.
//
// This file is loaded via fs.readFileSync by the hooks.mjs load() hook.
// The placeholder __HOOKS_SHARED_URL__ is replaced at load-time with
// the absolute file:// URL of hooks/shared.mjs so imports resolve correctly
// even though this code is served under a virtual 'envtrap:' URL.
//
// Intercepts: spawn, spawnSync, exec, execSync, execFile, execFileSync, fork

import {
  spawn as _spawn,
  exec as _exec,
  execFile as _execFile,
  fork as _fork,
  spawnSync as _spawnSync,
  execSync as _execSync,
  execFileSync as _execFileSync,
  ChildProcess,
} from 'node:child_process';

import {
  getCallerFile,
  isPathExcluded,
} from '__HOOKS_SHARED_URL__';

export { ChildProcess } from 'node:child_process';

// ---------------------------------------------------------------------------
// Config (read once from env at module init)
// ---------------------------------------------------------------------------

const secretsMap = (() => {
  try { return JSON.parse(process.env.__ENVTRAP_SECRETS_MAP__ || '{}'); }
  catch { return {}; }
})();

const pathExclusions = (() => {
  try { return JSON.parse(process.env.__ENVTRAP_PATH_EXCLUSIONS__ || '[]'); }
  catch { return []; }
})();

const channelMode = (() => {
  try { return JSON.parse(process.env.__ENVTRAP_CONFIG_MODES__ || '{}').child_process || 'warn'; }
  catch { return 'warn'; }
})();

// ---------------------------------------------------------------------------
// Core check
// ---------------------------------------------------------------------------

function checkEnv(env, command) {
  if (!env || typeof env !== 'object') return;
  if (channelMode === 'off') return;

  const caller = getCallerFile();
  if (caller && isPathExcluded(caller, pathExclusions)) return;

  for (const name in secretsMap) {
    const value = secretsMap[name];
    if (name in env && env[name] === value) {
      process.stderr.write(
        '[envtrap] Child process leak: secret "' + name + '" passed to: ' + command + '\n'
      );
      if (channelMode === 'block') {
        throw new Error('[envtrap] child_process block: env key "' + name + '" passed to child process');
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Wrapped exports
// ---------------------------------------------------------------------------

export function spawn(command, args, options) {
  if (options?.env) checkEnv(options.env, command);
  return _spawn(command, args ?? [], options ?? {});
}

export function exec(command, options, callback) {
  if (options && typeof options === 'object' && options.env) checkEnv(options.env, command);
  if (typeof options === 'function') return _exec(command, options);
  if (typeof callback === 'function') return _exec(command, options, callback);
  return _exec(command, options);
}

export function execFile(file, args, options, callback) {
  if (options && typeof options === 'object' && options.env) checkEnv(options.env, file);
  if (typeof args === 'function') return _execFile(file, args);
  if (typeof options === 'function') return _execFile(file, args, options);
  if (typeof callback === 'function') return _execFile(file, args, options, callback);
  return _execFile(file, args, options);
}

export function fork(modulePath, args, options) {
  if (options?.env) checkEnv(options.env, modulePath);
  return _fork(modulePath, args ?? [], options ?? {});
}

export function spawnSync(command, args, options) {
  if (options?.env) checkEnv(options.env, command);
  return _spawnSync(command, args ?? [], options ?? {});
}

export function execSync(command, options) {
  if (options?.env) checkEnv(options.env, command);
  return _execSync(command, options ?? {});
}

export function execFileSync(file, args, options) {
  if (options?.env) checkEnv(options.env, file);
  return _execFileSync(file, args ?? [], options ?? {});
}

export default {
  spawn, exec, execFile, fork, spawnSync, execSync, execFileSync, ChildProcess,
};
