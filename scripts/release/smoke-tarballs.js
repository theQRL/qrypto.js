#!/usr/bin/env node
// Installs each released tarball into a throwaway CommonJS and ESM project
// and round-trips a require()/import() to catch packaging regressions before
// the publish job runs.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';

const args = process.argv.slice(2);
if (args[0] === '--') args.shift();

const [
  releasedPackagesPath = 'dist/released-packages.tsv',
  tarballDirectory = 'dist/tarballs',
] = args;

const releasedPackages = readFileSync(releasedPackagesPath, 'utf8')
  .trim()
  .split('\n')
  .filter(Boolean)
  .map((line) => {
    const [packagePath, name, version, releaseTag, tarballFile] = line.split('\t');
    return { packagePath, name, version, releaseTag, tarballName: tarballFile };
  });

if (releasedPackages.length === 0) {
  console.log('No released packages to smoke test');
  process.exit(0);
}

const tarballs = releasedPackages.map((pkg) => resolve(tarballDirectory, pkg.tarballName));
const npmCache =
  process.env.npm_config_cache ||
  mkdtempSync(resolve(tmpdir(), 'qrypto-release-npm-cache-'));

const run = (command, runArgs, cwd) => {
  execFileSync(command, runArgs, {
    cwd,
    stdio: 'inherit',
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_ignore_scripts: 'true',
      npm_config_cache: npmCache,
    },
  });
};

const makeProject = (type) => {
  const directory = mkdtempSync(resolve(tmpdir(), `qrypto-release-${type}-`));
  writeFileSync(
    resolve(directory, 'package.json'),
    `${JSON.stringify(
      {
        name: `qrypto-release-smoke-${type}`,
        private: true,
        type,
      },
      null,
      2,
    )}\n`,
  );
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', ...tarballs], directory);
  return directory;
};

const cjsProject = makeProject('commonjs');
writeFileSync(
  resolve(cjsProject, 'smoke.cjs'),
  `const packages = ${JSON.stringify(releasedPackages.map((pkg) => pkg.name), null, 2)};
for (const name of packages) {
\tconst mod = require(name);
\tif (mod == null) throw new Error(\`No CommonJS export for \${name}\`);
\tconsole.log(\`required \${name}\`);
}
`,
);
run('node', ['smoke.cjs'], cjsProject);

const esmProject = makeProject('module');
writeFileSync(
  resolve(esmProject, 'smoke.mjs'),
  `const packages = ${JSON.stringify(releasedPackages.map((pkg) => pkg.name), null, 2)};
for (const name of packages) {
\tconst mod = await import(name);
\tif (mod == null) throw new Error(\`No ESM export for \${name}\`);
\tconsole.log(\`imported \${name}\`);
}
`,
);
run('node', ['smoke.mjs'], esmProject);

console.log(
  `Smoke-tested ${releasedPackages.length} package tarball${releasedPackages.length === 1 ? '' : 's'} from ${basename(
    dirname(tarballs[0]),
  )}`,
);
