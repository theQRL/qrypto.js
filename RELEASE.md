# Release Process

This repo uses Changesets to keep `@theqrl/dilithium5` and `@theqrl/mldsa87`
in lockstep versions and to publish them together.

## Pre-requisites

- [ ] Ensure the working tree is clean (no uncommitted changes).
- [ ] Run tests: `npm test`.
- [ ] Run lint checks: `npm run lint`.
- [ ] Verify builds: `npm run build`.
- [ ] Confirm npm auth and registry access for publishing.

## Create a changeset

```bash
npm run changeset
```

Select both packages and choose the version bump (patch/minor/major).

## Version packages

```bash
npm run version-packages
```

This updates package versions and changelogs based on the changesets.

## Build and publish

```bash
npm run release
```

This runs the Turbo build and publishes both packages to npm.

## Dry run (optional)

Use `npm pack --dry-run` from each package directory if you want to inspect
package contents before publishing.
