# Release Process

Releases are automated via [multi-semantic-release](https://github.com/dhoulb/multi-semantic-release). When code is merged to `main`, GitHub Actions analyzes commit messages, determines version numbers, generates release notes, creates Git tags, and publishes to npm.

`@theqrl/dilithium5` and `@theqrl/mldsa87` are versioned **independently**: each package's version is derived from the commits that touch it (current versions differ, e.g. 1.x vs 2.x). A commit touching shared files releases both.

## Commit Message Format

This project uses [Conventional Commits](https://www.conventionalcommits.org/) to determine version bumps:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types and Version Bumps

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `fix:` | Patch (0.0.x) | `fix: correct NTT implementation` |
| `feat:` | Minor (0.x.0) | `feat: add context parameter support` |
| `feat!:` or `BREAKING CHANGE:` | Major (x.0.0) | `feat!: change keypair API` |

Other prefixes (`docs:`, `chore:`, `test:`, `refactor:`, `ci:`, `style:`) do not trigger releases.

### Examples

**Patch Release** (bug fix):
```
fix: correct polynomial coefficient bounds check
```

**Minor Release** (new feature):
```
feat: add streaming signature verification
```

**Major Release** (breaking change):
```
feat!: rename generateKeypair to generateKeyPair

BREAKING CHANGE: The generateKeypair function has been renamed to generateKeyPair for consistency.
```

## Best Practices

1. **Atomic commits**: Each commit should represent a single logical change
2. **Descriptive messages**: Keep the first line under 72 characters
3. **Reference issues**: Use `Fixes #123` or `Closes #456` in the footer when applicable

## Skipping Releases

To merge without triggering a release, use non-release commit types (`chore:`, `docs:`, `test:`, etc.) or include `[skip ci]` in the commit message.

## Recovering an Orphaned Release

The release pipeline creates git tags and GitHub releases in the `prepare`
job (via multi-semantic-release) **before** npm publishing happens in the
later `publish` job. If `smoke-node20` or `publish` fails after `prepare`
succeeded, the tag and GitHub release exist with **no npm artifact** — and
semantic-release will *not* retry that version on the next run (the tag
already exists). The `Verify packages are live on npm` step in
[release.yml](.github/workflows/release.yml) turns this state into a loud
failure instead of a silent gap.

To recover (requires npm publish rights on the `@theqrl` org):

1. Download the `release-candidate-tarballs` artifact from the failed
   workflow run (Actions → the run → Artifacts). These are the exact bytes
   that were smoke-tested; do **not** rebuild locally.
2. For each orphaned package, publish the prepared tarball:

   ```bash
   npm publish dist/tarballs/theqrl-<package>-<version>.tgz --access public
   ```

   (With npm trusted publishing, a manual publish requires a granular
   token or `npm login` — provenance will be absent on a manual publish;
   note that in the release notes.)
3. Verify: `npm view @theqrl/<package>@<version> version` returns the
   version.
4. If the artifact has expired (5-day retention), the affected version
   number is burned: land a trivial `fix:` commit and let the pipeline cut
   the next patch version end-to-end instead. Never move or delete the
   existing tag.
