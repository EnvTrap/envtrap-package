// src/config/PathMatcher.ts
// Glob-based path exclusion helper.
//
// Extracted here so it can be imported by the scanner and other modules
// without coupling them to the config loader (which pulls in fs/path).

/**
 * Returns true if filePath matches any glob pattern in the given list.
 *
 * Supports:
 *   - Exact paths:    "src/lib/secret.ts"
 *   - Wildcards:      "test/**"
 *   - Double globs:   "**\/__tests__\/**"
 */
export function isPathExcluded(filePath: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false;

  const normalized = filePath.replace(/\\/g, '/');

  for (const pattern of patterns) {
    let p = pattern.replace(/\\/g, '/');

    // Make non-rooted, non-glob-leading patterns match anywhere in the tree
    if (!p.startsWith('/') && !p.startsWith('**')) {
      p = '**/' + p;
    }

    const parts = p.split('**');
    const regexParts = parts.map((part) =>
      part
        .replace(/[-\/\\^$+?.()|[\]{}]/g, '\\$&')
        .replace(/\*/g, '.*'),
    );
    const regex = new RegExp('^' + regexParts.join('.*') + '$');

    if (regex.test(normalized) || regex.test('/' + normalized)) return true;
  }

  return false;
}
