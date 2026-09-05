// scripts/copy-hooks.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const filesToCopy = [
  ['src/hooks/hooks.mjs', 'dist/hooks/hooks.mjs'],
  ['src/hooks/shared.mjs', 'dist/hooks/shared.mjs'],
  ['src/hooks/virtual/child-process.mjs', 'dist/hooks/virtual/child-process.mjs'],
  ['src/hooks/virtual/dns.mjs', 'dist/hooks/virtual/dns.mjs'],
  ['src/hooks/hooks.mjs', 'dist/hooks.mjs'],
];

for (const [srcRel, destRel] of filesToCopy) {
  const src = path.resolve(root, srcRel);
  const dest = path.resolve(root, destRel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}
