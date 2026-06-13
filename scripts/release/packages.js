#!/usr/bin/env node
// Snapshots, diffs, and lists publishable workspace packages.
// Used by the release workflow to detect which packages were bumped by
// multi-semantic-release and emit GitHub Actions outputs + a TSV the
// downstream pack/publish/SLSA jobs iterate over.

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const workspaceRoots = ['packages'];

const readJson = (filePath) => JSON.parse(readFileSync(filePath, 'utf8'));

const packageDirectories = () =>
  workspaceRoots.flatMap((root) => {
    const absRoot = join(repoRoot, root);
    if (!existsSync(absRoot)) return [];
    return readdirSync(absRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => join(root, entry.name))
      .filter((packagePath) => existsSync(join(repoRoot, packagePath, 'package.json')));
  });

export const publishablePackages = () =>
  packageDirectories()
    .map((packagePath) => {
      const manifest = readJson(join(repoRoot, packagePath, 'package.json'));
      return {
        path: packagePath,
        name: manifest.name,
        version: manifest.version,
        private: manifest.private === true,
        access: manifest.publishConfig?.access,
      };
    })
    .filter((pkg) => pkg.name && pkg.version && !pkg.private && pkg.access === 'public')
    .sort((a, b) => a.name.localeCompare(b.name));

export const releaseTag = (pkg) => `${pkg.name}@${pkg.version}`;

export const tarballName = (pkg) => `${pkg.name.replace(/^@/, '').replace('/', '-')}-${pkg.version}.tgz`;

const ensureParentDirectory = (filePath) => mkdirSync(dirname(filePath), { recursive: true });

const writeJson = (filePath, value) => {
  ensureParentDirectory(filePath);
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
};

const writeGithubOutput = (values) => {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  const lines = Object.entries(values).map(([key, value]) => `${key}=${value}`);
  writeFileSync(outputPath, `${lines.join('\n')}\n`, { flag: 'a' });
};

const snapshot = (outputPath) => {
  writeJson(outputPath, publishablePackages());
};

const diff = (beforePath, outputPath) => {
  const before = new Map(readJson(beforePath).map((pkg) => [pkg.name, pkg.version]));
  const released = publishablePackages()
    .filter((pkg) => before.get(pkg.name) !== pkg.version)
    .map((pkg) => ({
      ...pkg,
      releaseTag: releaseTag(pkg),
      tarballName: tarballName(pkg),
    }));

  writeJson(outputPath, released);

  const tsvPath = join(dirname(outputPath), 'released-packages.tsv');
  const tsv = released
    .map((pkg) => [pkg.path, pkg.name, pkg.version, pkg.releaseTag, pkg.tarballName].join('\t'))
    .join('\n');
  writeFileSync(tsvPath, tsv ? `${tsv}\n` : '');

  writeGithubOutput({
    released: released.length > 0 ? 'true' : 'false',
    count: String(released.length),
    packages: released.map((pkg) => pkg.name).join(','),
  });
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const [command, firstArg, secondArg] = process.argv.slice(2);

  if (command === 'snapshot' && firstArg) {
    snapshot(firstArg);
  } else if (command === 'diff' && firstArg && secondArg) {
    diff(firstArg, secondArg);
  } else if (command === 'list') {
    for (const pkg of publishablePackages()) {
      console.log(`${pkg.path}\t${pkg.name}\t${pkg.version}`);
    }
  } else {
    console.error('Usage: packages.js <snapshot output.json | diff before.json output.json | list>');
    process.exitCode = 1;
  }
}
