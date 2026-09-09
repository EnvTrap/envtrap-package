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

  if (pathExclusions.length > 0) {
    const caller = getCallerFile();
    if (caller && isPathExcluded(caller, pathExclusions)) return;
  }

  for (const name in secretsMap) {
    const value = secretsMap[name];
    if (name in env && env[name] === value) {
      process.stderr.write(
        '[envtrap] Child process leak: secret "' + name + '" passed to: ' + command + '\n'
      );
      if (channelMode === 'block') {
        throw new Error('[envtrap] child_process block: env key "' + name + '" passed to child');
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Wrapped exports
// ---------------------------------------------------------------------------

export function spawn(command, args, options) {
  let actualArgs = args;
  let actualOpts = options;
  if (typeof actualArgs === 'object' && actualArgs !== null && !Array.isArray(actualArgs)) {
    actualOpts = actualArgs;
    actualArgs = [];
  }
  actualOpts = actualOpts && typeof actualOpts === 'object' ? actualOpts : {};
  const env = actualOpts.env ?? process.env;
  checkEnv(env, command);
  return _spawn(command, actualArgs ?? [], actualOpts);
}

export function exec(command, options, callback) {
  let actualOpts = options;
  let actualCb = callback;
  if (typeof actualOpts === 'function') {
    actualCb = actualOpts;
    actualOpts = {};
  } else if (!actualOpts || typeof actualOpts !== 'object') {
    actualOpts = {};
  }
  const env = actualOpts.env ?? process.env;
  checkEnv(env, command);
  if (typeof actualCb === 'function') {
    return _exec(command, actualOpts, actualCb);
  }
  return _exec(command, actualOpts);
}

export function execFile(file, args, options, callback) {
  let actualArgs = [];
  let actualOpts = {};
  let actualCb = callback;

  if (Array.isArray(args)) {
    actualArgs = args;
    if (typeof options === 'function') {
      actualCb = options;
    } else if (options && typeof options === 'object') {
      actualOpts = options;
    }
  } else if (typeof args === 'function') {
    actualCb = args;
  } else if (args && typeof args === 'object') {
    actualOpts = args;
    if (typeof options === 'function') {
      actualCb = options;
    }
  } else if (typeof options === 'function') {
    actualCb = options;
  } else if (options && typeof options === 'object') {
    actualOpts = options;
  }

  actualOpts = actualOpts && typeof actualOpts === 'object' ? actualOpts : {};
  const env = actualOpts.env ?? process.env;
  checkEnv(env, file);

  if (typeof actualCb === 'function') {
    return _execFile(file, actualArgs, actualOpts, actualCb);
  }
  return _execFile(file, actualArgs, actualOpts);
}

export function fork(modulePath, args, options) {
  let actualArgs = args;
  let actualOpts = options;
  if (typeof actualArgs === 'object' && actualArgs !== null && !Array.isArray(actualArgs)) {
    actualOpts = actualArgs;
    actualArgs = [];
  }
  actualOpts = actualOpts && typeof actualOpts === 'object' ? actualOpts : {};
  const env = actualOpts.env ?? process.env;
  checkEnv(env, modulePath);
  return _fork(modulePath, actualArgs ?? [], actualOpts);
}

export function spawnSync(command, args, options) {
  let actualArgs = args;
  let actualOpts = options;
  if (typeof actualArgs === 'object' && actualArgs !== null && !Array.isArray(actualArgs)) {
    actualOpts = actualArgs;
    actualArgs = [];
  }
  actualOpts = actualOpts && typeof actualOpts === 'object' ? actualOpts : {};
  const env = actualOpts.env ?? process.env;
  checkEnv(env, command);
  return _spawnSync(command, actualArgs ?? [], actualOpts);
}

export function execSync(command, options) {
  const actualOpts = options && typeof options === 'object' ? options : {};
  const env = actualOpts.env ?? process.env;
  checkEnv(env, command);
  return _execSync(command, actualOpts);
}

export function execFileSync(file, args, options) {
  let actualArgs = args;
  let actualOpts = options;
  if (typeof actualArgs === 'object' && actualArgs !== null && !Array.isArray(actualArgs)) {
    actualOpts = actualArgs;
    actualArgs = [];
  }
  actualOpts = actualOpts && typeof actualOpts === 'object' ? actualOpts : {};
  const env = actualOpts.env ?? process.env;
  checkEnv(env, file);
  return _execFileSync(file, actualArgs ?? [], actualOpts);
}

export default {
  spawn, exec, execFile, fork, spawnSync, execSync, execFileSync, ChildProcess,
};
