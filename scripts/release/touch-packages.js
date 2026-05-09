#!/usr/bin/env node
// Writes a fresh .release-touch marker into each publishable workspace package
// so multi-semantic-release detects a change scoped to every package and cuts
// a release for it. Use when you need to force-publish patches that don't
// otherwise produce per-package commits (e.g. cross-cutting tooling fixes).

import { randomBytes } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const packagesDir = join(repoRoot, 'packages');
const markerName = '.release-touch';
const marker = `${new Date().toISOString()}\n${randomBytes(16).toString('hex')}\n`;

const hasPackageJson = (path) => {
  try {
    return statSync(join(path, 'package.json')).isFile();
  } catch {
    return false;
  }
};

const publishablePackages = readdirSync(packagesDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => join(packagesDir, entry.name))
  .filter(hasPackageJson)
  .map((path) => ({
    path,
    manifest: JSON.parse(readFileSync(join(path, 'package.json'), 'utf8')),
  }))
  .filter(
    ({ manifest }) =>
      manifest.name &&
      manifest.version &&
      manifest.private !== true &&
      manifest.publishConfig?.access === 'public',
  )
  .sort((a, b) => a.manifest.name.localeCompare(b.manifest.name));

if (publishablePackages.length === 0) {
  console.error('No publishable packages found under packages/');
  process.exit(1);
}

for (const { path, manifest } of publishablePackages) {
  writeFileSync(join(path, markerName), marker);
  console.info(`Touched ${manifest.name}`);
}
