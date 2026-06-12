# Contributing to qrypto.js

This monorepo publishes two npm packages — `@theqrl/mldsa87` (ML-DSA-87,
FIPS 204) and `@theqrl/dilithium5` (CRYSTALS-Dilithium Round 3, legacy) —
from `packages/`. It is production cryptographic code: the bar for changes
is correctness first, and several invariants below are enforced by CI.

## Getting started

```bash
npm install
npm test            # all tests, both packages (450+)
npm run lint        # eslint + prettier
npm run build       # rollup dual ESM/CJS builds into dist/
npm run check-shared  # shared-file sync check (see below)
```

Node ≥ 20.19 (`.nvmrc` says 22). CI tests on Node 20.x, 22.x, and 24.x.

## Commit messages drive releases

Releases are fully automated from conventional commits on `main`
(see [RELEASE.md](RELEASE.md)): `fix:` → patch, `feat:` → minor,
`feat!:`/`BREAKING CHANGE:` → major; `chore:`/`docs:`/`test:`/`ci:` do not
release. The two packages version independently — a commit touching shared
files releases both.

## Invariant: shared files stay byte-identical

The two packages deliberately duplicate their common modules so each npm
artifact is self-contained. Eight files are required to remain
**byte-identical** between `packages/dilithium5/src/` and
`packages/mldsa87/src/` (the list lives in
[scripts/check-shared-files.js](scripts/check-shared-files.js)):

`random.js`, `utils.js`, `reduce.js`, `ntt.js`, `rounding.js`,
`polyvec.js`, `fips202.js`, `index.js`

**When you change one of these files, apply the identical change to both
packages** (`cp` is the safest tool). `npm run check-shared` verifies it;
CI runs it in the lint job and in the release preflight, so divergence
fails the build. A security fix applied to one package but not the other
creates a silent divergence — that is exactly what this gate exists to
prevent.

The remaining files (`const.js`, `symmetric-shake.js`, `poly.js`,
`packing.js`, `sign.js`, `index.d.ts`) differ only by algorithm deltas
(challenge size 32 vs 64 bytes, FIPS 204 context/hedging, naming). When a
change applies to both algorithms, port it to both files in the same PR.

## Invariant: dist/ is committed and must match src/

`dist/` (dual ESM/CJS builds) is checked into git. After any `src/` change,
run `npm run build` and commit the resulting `dist/` changes. CI's
`dist-check` job and the release preflight fail when `dist/` is stale.
This keeps the published artifact reviewable in git and enables the
fuzzer's src↔dist agreement oracle.

Note: the CJS build **bundles** `@noble/hashes` (it is ESM-only). See
SECURITY.md "Bundled Dependencies in the CJS Artifact" for the
dependency-patch playbook this implies.

## Updating pinned verification upstreams

The verification workflows clone external repositories at **pinned commit
SHAs** (defined as `env:` values at the top of each workflow) so upstream
changes cannot silently alter what "verification passed" means:

| Pin | Workflow | What it is |
|---|---|---|
| `ACVP_SERVER_PIN` | acvp.yml | NIST ACVP ML-DSA vectors |
| `WYCHEPROOF_PIN` | wycheproof.yml | C2SP Wycheproof ML-DSA vectors |
| `GO_QRLLIB_MLDSA87_PIN` | cross-verify.yml | go-qrllib **v0.9.0** for ML-DSA-87 interop |
| `GO_QRLLIB_DILITHIUM5_PIN` | cross-verify.yml | go-qrllib **v0.8.0** — frozen, see below |
| `PQCRYSTALS_MLDSA87_PIN` | cross-verify.yml | C reference (FIPS 204) |
| `PQCRYSTALS_DILITHIUM5_PIN` | cross-verify.yml | C reference (Round 3) — frozen |

**Bump procedure** (quarterly, or when upstream publishes something we
need): pick the new upstream commit SHA, update the `env:` value with a
dated comment, and run the affected workflow via `workflow_dispatch` on
your branch before merging. If a new vector legitimately fails, fix the
implementation or document why the vector does not apply — never bump past
a failure silently.

**Do not bump** `GO_QRLLIB_DILITHIUM5_PIN` (`b2ee4790…` = **v0.8.0**, the
last go-qrllib release containing `crypto/dilithium` — upstream removed it
in **v0.9.0**, commit `1ae1760`) or `PQCRYSTALS_DILITHIUM5_PIN`
(`ac743d5…`, Round 3): these are permanently historical references for the
frozen Dilithium5 scheme. The `cross-verify/go.mod` pin for the Go
*verifier* direction is similarly frozen.

## Fuzzing

```bash
node scripts/fuzz/run-campaign.mjs --profile quick  # 10k iters, runs in CI per push
node scripts/fuzz/run-campaign.mjs --profile weekly # 100k, scheduled Sundays
node scripts/fuzz/run-campaign.mjs --profile deep   # 1M — audit-level review only, run on demand
```

The `deep` profile is deliberately not on any schedule: reserve it for
audit-level code review (e.g. before a major release or when crypto-core
code changes), launched via `workflow_dispatch` on fuzz-scheduled.yml or
locally.

Eight harnesses run in parallel (verify / open / unpack-sig / verify-dist,
for each package). Findings are written under `packages/*/fuzz/corpus/`
(gitignored) through a save budget that caps per-class and total saves —
expected validation throws are counted but never persisted. The campaign
refuses to start over a bloated corpus; `--clean-corpus` purges it. Exit
codes: 0 clean, 1 interesting, ≥2 critical.

## Coverage policy

Coverage is **100% — statements, branches, functions, lines — on both
packages**, enforced by the Codecov targets in `codecov.yml`. "Can't reach
100%" is treated as a design smell, not an excuse: if a branch is
unreachable (or has no deterministic trigger), exclude it at the source
with a `/* c8 ignore */` marker and an **adjacent comment explaining why
it cannot be exercised**. The exclusions flow into the lcov upload, so
Codecov and the local `npm run coverage` measure the same 100%.

Accepted rationale categories (see existing sites in `sign.js` /
`poly.js` for the house style):

- **Statistically unreachable**: rejection-sampling paths with no known
  deterministic trigger (e.g. the ct0 norm check, hint-count overflow,
  SHAKE re-squeeze). These are exercised by long fuzz campaigns instead.
- **Defensively unreachable**: guards that a caller cannot reach through
  the public API but that protect against future internal misuse (e.g.
  the `typeof` check inside `hexToBytes`, the `result !== 0` tripwire in
  `cryptoSign`).

A PR adding an ignore without a rationale comment, or whose rationale
amounts to "hard to test", should be rejected — write the test instead.

## Error & invariant policy

Inherited from go-qrllib's panic policy, translated to JavaScript. The
library distinguishes three failure classes — keep new code consistent
with them:

1. **Malformed untrusted input to verification-shaped APIs** —
   `cryptoSignVerify` returns `false` and `cryptoSignOpen` returns
   `undefined` for wrong-typed / wrong-length signatures, messages,
   public keys, and signed messages; they **never throw on attacker-
   controllable bytes** (`cryptoSignOpenWithReason` reports a typed
   reason instead). One documented exception: a `ctx` argument of the
   wrong *type* throws `TypeError` — context is programmer-supplied
   configuration, not attacker data (Go's static typing makes this case
   inexpressible; a throw is the JS equivalent of that compile error).
2. **Invalid caller input to key-handling APIs** — `cryptoSignKeypair`,
   `cryptoSignSignature`, `cryptoSign` throw a typed `Error`/`TypeError`
   immediately on wrong buffer sizes, wrong types, invalid hex, or
   oversized context. These are programmer errors; failing fast beats
   producing garbage with key material.
3. **Invariant tripwires** — internal preconditions that cannot fail
   unless the library itself regresses **throw with a clear message** so
   a future regression fails loudly in tests rather than silently
   corrupting key material. Existing sites: the binary-hint and
   OMEGA-count guards in `packSig`, the post-wipe verification in
   `zeroize`, the all-zero output check in `randomBytes`, the internal
   seed/ctilde-length guards in `polyvec.js` / `symmetric-shake.js` /
   `polyChallenge`. Every tripwire carries a comment stating the
   invariant it enforces; new ones must too.

## Public API surface policy

`src/index.js` currently re-exports every internal module, and
`src/index.d.ts` types the full surface. Only the **documented API**
(README "API Reference": `cryptoSignKeypair`, `cryptoSign`,
`cryptoSignSignature`, `cryptoSignVerify`, `cryptoSignOpen`,
`cryptoSignOpenWithReason`, the deterministic wrappers, the byte-size
constants, and `zeroize`/`isZero`/`zeroizePolyVec`) is the stable contract.
Everything else is exported for testing/interop, is marked `@deprecated`
in the `.d.ts` as internal, and **will move behind a subpath or disappear
at the next major version**. Don't grow the internal surface: new helpers
that aren't part of the documented API should not be added to the README
or relied upon downstream.

## Release trust model (maintainers)

- Publishing uses **npm trusted publishing** (OIDC) from
  [release.yml](.github/workflows/release.yml) — no long-lived npm token
  exists. Artifacts get SLSA L3 provenance, SBOMs, and Sigstore
  attestations; the publish job verifies each version is actually served
  by the registry before attaching release assets.
- The `prepare` job pushes release commits/tags through `BYPASS_SSH_KEY`,
  a deploy key that bypasses branch protection, gated by the
  `npm-publish` environment. Rotate it like any production credential and
  keep its scope to this repository only.
- If a release fails between tagging and npm publish, follow
  RELEASE.md "Recovering an Orphaned Release".

## PR checklist

- [ ] `npm test` green (both packages)
- [ ] `npm run lint` clean
- [ ] `npm run check-shared` passes (if you touched a shared file: edited both packages)
- [ ] `npm run build` run and `dist/` changes committed (if you touched `src/`)
- [ ] Conventional-commit message with the intended release semantics
- [ ] Security-relevant change? Update SECURITY.md and consider the
      dependency-patch playbook / downstream wallet.js implications
