#!/usr/bin/env node

/**
 * Verifies that shared source files between dilithium5 and mldsa87 remain
 * byte-identical. A security fix applied to one package but not the other
 * creates a silent divergence.
 */

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const SHARED_FILES = [
  'src/random.js',
  'src/utils.js',
  'src/reduce.js',
  'src/ntt.js',
  'src/rounding.js',
  'src/polyvec.js',
  'src/fips202.js',
  'src/index.js',
];

const pkg1 = resolve(root, 'packages/dilithium5');
const pkg2 = resolve(root, 'packages/mldsa87');

let failed = false;

for (const file of SHARED_FILES) {
  const path1 = resolve(pkg1, file);
  const path2 = resolve(pkg2, file);

  const content1 = readFileSync(path1);
  const content2 = readFileSync(path2);

  if (!content1.equals(content2)) {
    console.error(`MISMATCH: ${file} differs between dilithium5 and mldsa87`);
    failed = true;
  }
}

if (failed) {
  console.error('\nShared files have diverged. Apply the same changes to both packages.');
  process.exit(1);
} else {
  console.log(`All ${SHARED_FILES.length} shared files are in sync.`);
}
