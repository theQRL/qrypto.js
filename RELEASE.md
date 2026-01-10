# Release Process

Releases are automated via [multi-semantic-release](https://github.com/dhoulb/multi-semantic-release).

Both `@theqrl/dilithium5` and `@theqrl/mldsa87` are released together with the same version.

## How It Works

1. Commits to `main` trigger the release workflow
2. multi-semantic-release analyzes commit messages to determine version bump
3. If releasable commits exist, it:
   - Bumps version in both `packages/*/package.json`
   - Generates/updates `CHANGELOG.md` in each package
   - Builds all packages via Turborepo
   - Publishes both packages to npm
   - Creates GitHub release with release notes
   - Commits version bumps back to repo

## Commit Message Format

Releases are triggered by [Conventional Commits](https://www.conventionalcommits.org/):

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `fix:` | Patch (0.0.x) | `fix: correct NTT implementation` |
| `feat:` | Minor (0.x.0) | `feat: add context parameter support` |
| `feat!:` or `BREAKING CHANGE:` | Major (x.0.0) | `feat!: change keypair API` |

Other prefixes (`chore:`, `docs:`, `test:`, `refactor:`) do not trigger releases.

## Manual Release (Emergency)

If automated release fails, you can release manually:

```bash
# Ensure clean working tree
git status

# Run tests and lint
npm test
npm run lint

# Build all packages
npm run build

# Verify package contents
cd packages/mldsa87 && npm pack --dry-run && cd ../..
cd packages/dilithium5 && npm pack --dry-run && cd ../..

# Publish (requires npm auth)
cd packages/mldsa87 && npm publish --access public && cd ../..
cd packages/dilithium5 && npm publish --access public && cd ../..

# Tag and push
git tag v<VERSION>
git push origin main --tags
```

## Trusted Publishing (OIDC)

This repo uses [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/) with OIDC - no npm tokens required.

**Setup on npmjs.com (required for each package):**

1. Go to npmjs.com → package → Settings → Publishing access
2. Add Trusted Publisher with:
   - **Owner:** `theQRL`
   - **Repository:** `qrypto.js`
   - **Workflow:** `test.yml`
   - **Environment:** `npm-publish`

Configure for both `@theqrl/mldsa87` and `@theqrl/dilithium5`.

**GitHub Environment:**
Create environment `npm-publish` in repo Settings → Environments.

**Required Secrets:**
- `GITHUB_TOKEN` - Automatically provided (no setup needed)

## Configuration

- `.releaserc.json` - semantic-release configuration (shared by both packages)
- Workflow: `.github/workflows/test.yml` (release job)

## Packages

| Package | npm |
|---------|-----|
| `@theqrl/mldsa87` | [npmjs.com/package/@theqrl/mldsa87](https://www.npmjs.com/package/@theqrl/mldsa87) |
| `@theqrl/dilithium5` | [npmjs.com/package/@theqrl/dilithium5](https://www.npmjs.com/package/@theqrl/dilithium5) |
