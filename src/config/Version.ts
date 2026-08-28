// src/config/Version.ts
// Resolves the package version dynamically from package.json.
//
// Single responsibility: Dynamic version resolution.

import * as path from 'path';
import * as fs from 'fs';

export function getVersion(): string {
  try {
    const pkgPath = path.resolve(__dirname, '../../package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      return pkg.version ?? 'unknown';
    }
  } catch {
    // Fail-silent fallback to keep runtime execution safe.
  }
  return 'unknown';
}
