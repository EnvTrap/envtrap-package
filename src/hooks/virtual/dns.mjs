// src/hooks/virtual/dns.mjs
// Virtual module served as 'envtrap:dns' for ESM imports.
//
// This file is loaded via fs.readFileSync by the hooks.mjs load() hook.
// The placeholder __HOOKS_SHARED_URL__ is replaced at load-time with
// the absolute file:// URL of hooks/shared.mjs so imports resolve correctly.
//
// Intercepts: all dns.* and dns.promises.* methods.

import * as _dns from 'node:dns';

import {
  getCallerFile,
  isPathExcluded,
  shannonEntropy,
  checkHighEntropyDns,
} from '__HOOKS_SHARED_URL__';

export * from 'node:dns';

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
  try { return JSON.parse(process.env.__ENVTRAP_CONFIG_MODES__ || '{}').dns || 'block'; }
  catch { return 'block'; }
})();

const entropyThreshold = parseFloat(process.env.__ENVTRAP_ENTROPY_THRESHOLD__ || '3.5');
const entropyMinLength = parseInt(process.env.__ENVTRAP_ENTROPY_MIN_LENGTH__ || '12', 10);

// ---------------------------------------------------------------------------
// Core check
// ---------------------------------------------------------------------------

function checkLookup(specifier) {
  if (typeof specifier !== 'string') return;
  if (channelMode === 'off') return;

  const caller = getCallerFile();
  if (caller && isPathExcluded(caller, pathExclusions)) return;

  for (const name in secretsMap) {
    const value = secretsMap[name];
    if (value && value.length >= 8 && specifier.includes(value)) {
      process.stderr.write(
        '[envtrap] DNS leak: secret "' + name + '" found in lookup of: ' + specifier + '\n'
      );
      if (channelMode === 'block') {
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

// ---------------------------------------------------------------------------
// Wrapped exports (callback-style)
// ---------------------------------------------------------------------------

export function lookup(hostname, options, callback) {
  checkLookup(hostname);
  return typeof options === 'function'
    ? _dns.lookup(hostname, options)
    : _dns.lookup(hostname, options, callback);
}

export function resolve(hostname, rrtype, callback) {
  checkLookup(hostname);
  return typeof rrtype === 'function'
    ? _dns.resolve(hostname, rrtype)
    : _dns.resolve(hostname, rrtype, callback);
}

export function resolve4(hostname, options, callback) {
  checkLookup(hostname);
  return typeof options === 'function'
    ? _dns.resolve4(hostname, options)
    : _dns.resolve4(hostname, options, callback);
}

export function resolve6(hostname, options, callback) {
  checkLookup(hostname);
  return typeof options === 'function'
    ? _dns.resolve6(hostname, options)
    : _dns.resolve6(hostname, options, callback);
}

export function resolveAny(hostname, callback)  { checkLookup(hostname); return _dns.resolveAny(hostname, callback); }
export function resolveCname(hostname, callback) { checkLookup(hostname); return _dns.resolveCname(hostname, callback); }
export function resolveMx(hostname, callback)    { checkLookup(hostname); return _dns.resolveMx(hostname, callback); }
export function resolveNaptr(hostname, callback) { checkLookup(hostname); return _dns.resolveNaptr(hostname, callback); }
export function resolveNs(hostname, callback)    { checkLookup(hostname); return _dns.resolveNs(hostname, callback); }
export function resolvePtr(hostname, callback)   { checkLookup(hostname); return _dns.resolvePtr(hostname, callback); }
export function resolveSoa(hostname, callback)   { checkLookup(hostname); return _dns.resolveSoa(hostname, callback); }
export function resolveSrv(hostname, callback)   { checkLookup(hostname); return _dns.resolveSrv(hostname, callback); }
export function resolveTxt(hostname, callback)   { checkLookup(hostname); return _dns.resolveTxt(hostname, callback); }

// ---------------------------------------------------------------------------
// Wrapped exports (promise-style)
// ---------------------------------------------------------------------------

const _p = _dns.promises;

export const promises = {
  ..._p,
  lookup:       async (h, o)   => { checkLookup(h); return _p.lookup(h, o); },
  resolve:      async (h, r)   => { checkLookup(h); return _p.resolve(h, r); },
  resolve4:     async (h, o)   => { checkLookup(h); return _p.resolve4(h, o); },
  resolve6:     async (h, o)   => { checkLookup(h); return _p.resolve6(h, o); },
  resolveAny:   async (h)      => { checkLookup(h); return _p.resolveAny(h); },
  resolveCname: async (h)      => { checkLookup(h); return _p.resolveCname(h); },
  resolveMx:    async (h)      => { checkLookup(h); return _p.resolveMx(h); },
  resolveNaptr: async (h)      => { checkLookup(h); return _p.resolveNaptr(h); },
  resolveNs:    async (h)      => { checkLookup(h); return _p.resolveNs(h); },
  resolvePtr:   async (h)      => { checkLookup(h); return _p.resolvePtr(h); },
  resolveSoa:   async (h)      => { checkLookup(h); return _p.resolveSoa(h); },
  resolveSrv:   async (h)      => { checkLookup(h); return _p.resolveSrv(h); },
  resolveTxt:   async (h)      => { checkLookup(h); return _p.resolveTxt(h); },
};

export default { ..._dns, promises, lookup, resolve, resolve4, resolve6,
  resolveAny, resolveCname, resolveMx, resolveNaptr, resolveNs,
  resolvePtr, resolveSoa, resolveSrv, resolveTxt };
