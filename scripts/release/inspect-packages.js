#!/usr/bin/env node
// Runs `npm pack --dry-run` for each publishable package and asserts that
// declared entrypoints are present, no forbidden files (lockfiles, secrets,
// node_modules, etc.) leak into the tarball, and repository.url matches the
// canonical URL required by npm provenance.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { publishablePackages } from './packages.js';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const npmCache =
  process.env.npm_config_cache ||
  mkdtempSync(resolve(tmpdir(), 'qrypto-pack-npm-cache-'));

const normalizePackagePath = (packagePath) =>
  packagePath.replace(/^\.\//, '').replace(/\\/g, '/');

const collectExportTargets = (value) => {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(collectExportTargets);
  if (value && typeof value === 'object') return Object.values(value).flatMap(collectExportTargets);
  return [];
};

const declaredEntrypoints = (manifest) => {
  const entries = [];
  for (const key of ['main', 'module', 'types', 'typings']) {
    if (typeof manifest[key] === 'string') entries.push([key, manifest[key]]);
  }
  if (typeof manifest.browser === 'string') entries.push(['browser', manifest.browser]);
  for (const target of collectExportTargets(manifest.exports)) {
    entries.push(['exports', target]);
  }
  return entries
    .filter(
      ([, target]) =>
        target.startsWith('./') ||
        target.startsWith('src/') ||
        target.startsWith('lib/') ||
        target.startsWith('dist/'),
    )
    .map(([key, target]) => [key, normalizePackagePath(target)]);
};

const forbiddenPatterns = [
  [/^node_modules\//, 'node_modules'],
  [/^coverage\//, 'coverage'],
  [/^\.turbo\//, '.turbo'],
  [/^\.secrets\.json$/, '.secrets.json'],
  [/\byarn\.lock$/, 'yarn.lock'],
  [/\bpnpm-lock\.yaml$/, 'pnpm-lock.yaml'],
  [/\bpackage-lock\.json$/, 'package-lock.json'],
  [/ copy\./, 'copy file'],
];

// npm provenance verifies the repository URL exactly. Allow either the bare
// HTTPS form or the `git+...git` form that semantic-release sometimes writes,
// but require the host/path to match the canonical repo.
const provenanceRepositoryUrls = new Set([
  'https://github.com/theQRL/qrypto.js',
  'https://github.com/theQRL/qrypto.js.git',
  'git+https://github.com/theQRL/qrypto.js.git',
]);

const packDryRun = (packagePath) => {
  const output = execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: join(repoRoot, packagePath),
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_ignore_scripts: 'true',
      npm_config_cache: npmCache,
    },
  });
  const [pack] = JSON.parse(output);
  return pack;
};

const errors = [];
const summaries = [];

for (const pkg of publishablePackages()) {
  const manifestPath = join(repoRoot, pkg.path, 'package.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const pack = packDryRun(pkg.path);
  const files = new Set(pack.files.map((file) => normalizePackagePath(file.path)));
  const entrypoints = declaredEntrypoints(manifest);

  if (Object.prototype.hasOwnProperty.call(manifest, 'gitHead')) {
    errors.push(`${pkg.name}: package.json must not contain a committed gitHead`);
  }

  if (!provenanceRepositoryUrls.has(manifest.repository?.url)) {
    errors.push(
      `${pkg.name}: repository.url must point at https://github.com/theQRL/qrypto.js for npm provenance verification`,
    );
  }

  if (entrypoints.length === 0) {
    errors.push(`${pkg.name}: no package entrypoint declared`);
  }

  for (const [key, entrypoint] of entrypoints) {
    if (!files.has(entrypoint)) {
      errors.push(`${pkg.name}: ${key} target ${entrypoint} is missing from npm pack output`);
    }
  }

  for (const file of files) {
    for (const [pattern, label] of forbiddenPatterns) {
      if (pattern.test(file)) {
        errors.push(`${pkg.name}: forbidden ${label} file in npm pack output: ${file}`);
      }
    }
  }

  const packageJsonInTarball = files.has('package.json');
  if (!packageJsonInTarball || !existsSync(manifestPath)) {
    errors.push(`${pkg.name}: package.json was not included in pack output`);
  }

  summaries.push(`${pkg.name}: ${files.size} files, ${pack.unpackedSize} unpacked bytes`);
}

for (const summary of summaries) console.info(summary);

if (errors.length > 0) {
  console.error('\nPackage inspection failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.info(`Inspected ${summaries.length} publishable package dry-runs`);
