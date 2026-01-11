# Release Process

Releases are automated via [multi-semantic-release](https://github.com/dhoulb/multi-semantic-release). When code is merged to `main`, GitHub Actions analyzes commit messages, determines version numbers, generates release notes, creates Git tags, and publishes to npm.

Both `@theqrl/dilithium5` and `@theqrl/mldsa87` are released together with the same version.

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
