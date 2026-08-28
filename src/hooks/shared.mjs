// src/hooks/shared.mjs
// Shared runtime helpers used by the main hooks.mjs (CJS path) AND
// injected into the virtual child_process / dns ESM modules (ESM path).
//
// These functions run inside the CHILD PROCESS, not the envtrap parent.
// They read configuration from __ENVTRAP_* env vars set by the parent.

// ---------------------------------------------------------------------------
// Stack-trace based caller resolution
// ---------------------------------------------------------------------------

/**
 * Walks the current call stack and returns the first non-internal,
 * non-envtrap file path. Used to check path exclusions.
 *
 * @returns Absolute file path string or null if none found.
 */
export function getCallerFile() {
  const stack = new Error().stack;
  if (!stack) return null;

  const lines = stack.split('\n');
  for (let i = 2; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    const match = /\(([^)]+)\)/.exec(line) || /at\s+([^\s]+)/.exec(line);
    if (!match) continue;

    let filePath = match[1];

    // Strip line:col suffix (e.g. "/foo/bar.ts:12:4" → "/foo/bar.ts")
    const parts = filePath.split(':');
    if (parts.length >= 3) {
      const last = parts[parts.length - 1];
      const secondLast = parts[parts.length - 2];
      if (/^\d+$/.test(last) && /^\d+$/.test(secondLast)) {
        filePath = parts.slice(0, -2).join(':');
      }
    } else if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      filePath = parts[0];
    }

    // Normalise file:// URLs
    if (filePath.startsWith('file://')) {
      try { filePath = new URL(filePath).pathname; } catch { /* ignore */ }
    }

    // Skip internal / envtrap frames
    if (
      !filePath ||
      filePath.includes('node:internal') ||
      filePath.includes('internal/') ||
      (!filePath.startsWith('/') && !filePath.startsWith('file://')) ||
      filePath.includes('hooks.mjs') ||
      filePath.includes('hooks.js') ||
      filePath.includes('node_modules/envtrap')
    ) continue;

    return filePath;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Path exclusion
// ---------------------------------------------------------------------------

/**
 * Returns true if filePath matches any glob pattern in the list.
 * Supports * wildcards and ** prefix matching.
 */
export function isPathExcluded(filePath, patterns) {
  if (!filePath || !patterns || patterns.length === 0) return false;

  const normalized = filePath.replace(/\\/g, '/');

  for (let pattern of patterns) {
    pattern = pattern.replace(/\\/g, '/');
    if (!pattern.startsWith('/') && !pattern.startsWith('**')) {
      pattern = '**/' + pattern;
    }
    const regexParts = pattern
      .split('**')
      .map((p) => p.replace(/[-\/\\^$+?.()|[\]{}]/g, '\\$&').replace(/\*/g, '.*'));
    const regex = new RegExp('^' + regexParts.join('.*') + '$');
    if (regex.test(normalized)) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

/**
 * Computes Shannon entropy of a string.
 * H = -Σ (f/n) * log2(f/n)
 */
export function shannonEntropy(str) {
  if (!str) return 0;

  const freq = Object.create(null);
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }

  let entropy = 0;
  const n = str.length;
  for (const ch in freq) {
    const p = freq[ch] / n;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// ---------------------------------------------------------------------------
// High-entropy DNS tunneling detection
// ---------------------------------------------------------------------------

/**
 * Returns true if any subdomain label of specifier has suspiciously high
 * Shannon entropy (potential base64/hex DNS-tunneled payload).
 */
export function checkHighEntropyDns(specifier, threshold, minLength) {
  if (typeof specifier !== 'string') return false;

  for (const label of specifier.split('.')) {
    if (label.length >= minLength && shannonEntropy(label) >= threshold) {
      return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Pre-redaction (for path-excluded callers)
// ---------------------------------------------------------------------------

/**
 * Replaces all known secret values in a chunk with a placeholder.
 * Used to sanitise stdout/stderr writes from excluded paths before
 * the parent process scans them.
 */
export function preRedact(chunk, secretsMap) {
  if (!chunk || !secretsMap) return chunk;

  let str = typeof chunk === 'string' ? chunk : chunk.toString('utf-8');
  let modified = false;

  for (const name in secretsMap) {
    const value = secretsMap[name];
    if (value && str.includes(value)) {
      str = str.split(value).join('[REDACTED: PATH_EXCLUDED]');
      modified = true;
    }
  }

  return modified
    ? (typeof chunk === 'string' ? str : Buffer.from(str, 'utf-8'))
    : chunk;
}
