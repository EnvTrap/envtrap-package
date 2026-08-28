// src/hooks/hooks.mjs
// Node.js ESM Customization Hook + CommonJS require() monkeypatch.
// Injected into the child process via NODE_OPTIONS="--import <path>/hooks.mjs"
//
// Responsibilities:
//   1. ESM loader: resolve() and load() hooks for child_process and dns
//   2. ESM loader: initialize() — receives MessagePort for live secret sync
//   3. Main thread: Module.prototype.require patch (CJS path)
//   4. Main thread: stdout/stderr pre-redaction for excluded paths (CJS path)
//   5. Main thread: process.env Proxy for runtime secret rotation

import { readFileSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import module from 'node:module';
import { isMainThread, MessageChannel } from 'node:worker_threads';
import * as realChildProcess from 'node:child_process';
import * as realDns from 'node:dns';

import {
  getCallerFile,
  isPathExcluded,
  shannonEntropy,
  checkHighEntropyDns,
  preRedact,
} from './shared.mjs';

// ---------------------------------------------------------------------------
// Runtime configuration (read from env vars set by the parent process)
// ---------------------------------------------------------------------------

const configModes = (() => {
  try { return JSON.parse(process.env.__ENVTRAP_CONFIG_MODES__ || '{}'); }
  catch { return {}; }
})();

const pathExclusions = (() => {
  try { return JSON.parse(process.env.__ENVTRAP_PATH_EXCLUSIONS__ || '[]'); }
  catch { return []; }
})();

const entropyThreshold = parseFloat(process.env.__ENVTRAP_ENTROPY_THRESHOLD__ || '3.5');
const entropyMinLength = parseInt(process.env.__ENVTRAP_ENTROPY_MIN_LENGTH__ || '12', 10);

/** Mutable — updated via MessagePort when the parent rotates secrets at runtime */
let secretsMap = (() => {
  try { return JSON.parse(process.env.__ENVTRAP_SECRETS_MAP__ || '{}'); }
  catch { return {}; }
})();

// ---------------------------------------------------------------------------
// ESM Loader — initialize()
// Receives the MessagePort transferred from the parent via module.register().
// ---------------------------------------------------------------------------

export function initialize(data) {
  if (data?.port) {
    data.port.on('message', (msg) => {
      if (msg?.type === 'secrets_update' && typeof msg.secretsMap === 'object') {
        secretsMap = msg.secretsMap;
      }
    });
    data.port.unref();
  }
}

// ---------------------------------------------------------------------------
// CJS Interception — child_process wrapper
// ---------------------------------------------------------------------------

function reportChildLeak(name, command) {
  process.stderr.write(
    '[envtrap] Child process leak: secret "' + name + '" passed to: ' + command + '\n'
  );
}

function checkChildEnv(env, command) {
  if (!env || typeof env !== 'object') return;
  const mode = configModes.child_process || 'warn';
  if (mode === 'off') return;

  const caller = getCallerFile();
  if (caller && isPathExcluded(caller, pathExclusions)) return;

  for (const name in secretsMap) {
    const value = secretsMap[name];
    if (name in env && env[name] === value) {
      reportChildLeak(name, command);
      if (mode === 'block') {
        throw new Error('[envtrap] child_process block: env key "' + name + '" passed to child');
      }
    }
  }
}

function wrapChildProcess(real) {
  const w = { ...real };
  w.spawn       = (cmd, a, o) => { if (o?.env) checkChildEnv(o.env, cmd); return real.spawn(cmd, a, o); };
  w.spawnSync   = (cmd, a, o) => { if (o?.env) checkChildEnv(o.env, cmd); return real.spawnSync(cmd, a, o); };
  w.execSync    = (cmd, o)    => { if (o?.env) checkChildEnv(o.env, cmd); return real.execSync(cmd, o); };
  w.execFileSync = (f, a, o)  => { if (o?.env) checkChildEnv(o.env, f);   return real.execFileSync(f, a, o); };
  w.exec = (cmd, o, cb) => {
    const opts = typeof o === 'object' && o !== null ? o : {};
    if (opts.env) checkChildEnv(opts.env, cmd);
    return real.exec(cmd, o, cb);
  };
  w.execFile = (f, a, o, cb) => {
    const opts = typeof o === 'object' && o !== null ? o : {};
    if (opts.env) checkChildEnv(opts.env, f);
    return real.execFile(f, a, o, cb);
  };
  w.fork = (mod, a, o) => {
    const opts = (!Array.isArray(a) && typeof a === 'object' && a !== null) ? a : (o || {});
    if (opts.env) checkChildEnv(opts.env, mod);
    return real.fork(mod, a, o);
  };
  Object.setPrototypeOf(w, real);
  return w;
}

// ---------------------------------------------------------------------------
// CJS Interception — dns wrapper
// ---------------------------------------------------------------------------

function reportDnsLeak(name, specifier) {
  process.stderr.write(
    '[envtrap] DNS leak: secret "' + name + '" found in lookup of: ' + specifier + '\n'
  );
}

function checkLookup(specifier) {
  if (typeof specifier !== 'string') return;
  const mode = configModes.dns || 'block';
  if (mode === 'off') return;

  const caller = getCallerFile();
  if (caller && isPathExcluded(caller, pathExclusions)) return;

  for (const name in secretsMap) {
    const value = secretsMap[name];
    if (value && value.length >= 8 && specifier.includes(value)) {
      reportDnsLeak(name, specifier);
      if (mode === 'block') {
        throw new Error('DNS resolution blocked by envtrap: potential secret leak in domain name');
      }
    }
  }

  if (checkHighEntropyDns(specifier, entropyThreshold, entropyMinLength)) {
    process.stderr.write(
      '[envtrap] DNS warning: high-entropy lookup detected: ' + specifier + '\n'
    );
  }
}

function wrapDns(real) {
  const w = { ...real };
  const dnsOps = [
    'lookup','resolve','resolve4','resolve6','resolveAny',
    'resolveCname','resolveMx','resolveNaptr','resolveNs',
    'resolvePtr','resolveSoa','resolveSrv','resolveTxt',
  ];
  for (const op of dnsOps) {
    const orig = real[op];
    w[op] = function(hostname, ...rest) {
      checkLookup(hostname);
      return orig.call(real, hostname, ...rest);
    };
  }
  const _p = real.promises;
  w.promises = { ..._p };
  for (const op of dnsOps) {
    const orig = _p[op];
    w.promises[op] = async function(hostname, ...rest) {
      checkLookup(hostname);
      return orig.call(_p, hostname, ...rest);
    };
  }
  Object.setPrototypeOf(w, real);
  return w;
}

// ---------------------------------------------------------------------------
// Main-thread setup (CJS require patch + stdout/stderr + MessageChannel)
// ---------------------------------------------------------------------------

if (isMainThread) {
  const Module = module.Module;
  const wrappedCP  = wrapChildProcess(realChildProcess);
  const wrappedDns = wrapDns(realDns);

  // CJS require patch
  const originalRequire = Module.prototype.require;
  Module.prototype.require = function(id) {
    if (id === 'child_process' || id === 'node:child_process') return wrappedCP;
    if (id === 'dns'           || id === 'node:dns')           return wrappedDns;
    return originalRequire.apply(this, arguments);
  };

  // stdout/stderr pre-redaction for excluded callers
  const origStdout = process.stdout.write.bind(process.stdout);
  const origStderr = process.stderr.write.bind(process.stderr);

  process.stdout.write = function(chunk, encoding, callback) {
    const caller = getCallerFile();
    const args = [...arguments];
    if (caller && isPathExcluded(caller, pathExclusions)) args[0] = preRedact(chunk, secretsMap);
    return origStdout(...args);
  };

  process.stderr.write = function(chunk, encoding, callback) {
    const caller = getCallerFile();
    const args = [...arguments];
    if (caller && isPathExcluded(caller, pathExclusions)) args[0] = preRedact(chunk, secretsMap);
    return origStderr(...args);
  };

  // Live secret sync via MessageChannel
  if (typeof module.register === 'function') {
    const { port1, port2 } = new MessageChannel();

    module.register(import.meta.url, { data: { port: port2 }, transferList: [port2] });

    function broadcastSecrets() {
      try { port1.postMessage({ type: 'secrets_update', secretsMap }); } catch { /* port closed */ }
    }

    const rawEnv = process.env;
    process.env = new Proxy(rawEnv, {
      set(target, prop, value) {
        const changed = target[prop] !== value;
        target[prop] = value;
        if (changed && typeof prop === 'string' && typeof value === 'string'
            && value.length >= entropyMinLength) {
          secretsMap[prop] = value;
          broadcastSecrets();
        }
        return true;
      },
      deleteProperty(target, prop) {
        const existed = prop in target;
        delete target[prop];
        if (existed && typeof prop === 'string' && prop in secretsMap) {
          delete secretsMap[prop];
          broadcastSecrets();
        }
        return true;
      },
    });

    port1.unref();
  }
}

// ---------------------------------------------------------------------------
// ESM Loader — resolve() and load()
// ---------------------------------------------------------------------------

const __hooksDir = dirname(fileURLToPath(import.meta.url));
const sharedUrl  = pathToFileURL(join(__hooksDir, 'shared.mjs')).href;

const CP_SPECIFIERS  = new Set(['child_process', 'node:child_process']);
const DNS_SPECIFIERS = new Set(['dns', 'node:dns']);

export async function resolve(specifier, context, nextResolve) {
  // Let imports from our own virtual modules pass through to real node: URLs
  const parentIsVirtual = context.parentURL?.startsWith('envtrap:');
  const parentIsHooks   = context.parentURL?.endsWith('hooks.mjs') ||
                           context.parentURL?.endsWith('hooks.js');

  if (CP_SPECIFIERS.has(specifier)) {
    return parentIsVirtual || parentIsHooks
      ? { url: 'node:child_process', shortCircuit: true }
      : { url: 'envtrap:child_process', shortCircuit: true };
  }

  if (DNS_SPECIFIERS.has(specifier)) {
    return parentIsVirtual || parentIsHooks
      ? { url: 'node:dns', shortCircuit: true }
      : { url: 'envtrap:dns', shortCircuit: true };
  }

  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url === 'envtrap:child_process') {
    const source = readFileSync(join(__hooksDir, 'virtual', 'child-process.mjs'), 'utf-8')
      .replaceAll('__HOOKS_SHARED_URL__', sharedUrl);
    return { format: 'module', shortCircuit: true, source };
  }

  if (url === 'envtrap:dns') {
    const source = readFileSync(join(__hooksDir, 'virtual', 'dns.mjs'), 'utf-8')
      .replaceAll('__HOOKS_SHARED_URL__', sharedUrl);
    return { format: 'module', shortCircuit: true, source };
  }

  return nextLoad(url, context);
}
