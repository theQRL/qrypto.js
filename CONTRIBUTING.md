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

CI resolves external code through more mechanisms than `git clone` — Go
module requirements, global tool installs, and the engines inside pinned
actions are all resolution paths, and **every one of them is pinned** so
upstream changes cannot silently alter what "verification passed" means.
The full matrix (a pin missing from this table is a bug):

| Pin | Where | What it is | Status |
|---|---|---|---|
| `ACVP_SERVER_PIN` | acvp.yml `env:` | NIST ACVP ML-DSA vectors | bump routinely |
| `WYCHEPROOF_PIN` | wycheproof.yml `env:` | C2SP Wycheproof ML-DSA vectors | bump routinely |
| `GO_QRLLIB_MLDSA87_PIN` | cross-verify.yml `env:` | go-qrllib **v0.9.0** clone — ML-DSA-87 Go→JS *sign* leg | bump routinely |
| `GO_QRLLIB_DILITHIUM5_PIN` | cross-verify.yml `env:` | go-qrllib **v0.8.0** clone — Dilithium5 Go→JS *sign* leg | **frozen**, see below |
| `PQCRYSTALS_MLDSA87_PIN` | cross-verify.yml `env:` | C reference (FIPS 204) | bump routinely |
| `PQCRYSTALS_DILITHIUM5_PIN` | cross-verify.yml `env:` | C reference (Round 3) | **frozen** |
| go-qrllib `v0.9.0` | `.github/cross-verify/mldsa87-go/go.mod` | resolves the ML-DSA-87 JS→Go *verify* leg | bump together with `GO_QRLLIB_MLDSA87_PIN` |
| go-qrllib `v0.1.3-0.20260108…` | `.github/cross-verify/dilithium5-go/go.mod` | resolves the Dilithium5 JS→Go *verify* leg (pre-removal snapshot) | **frozen** |
| `npm@11.17.0` | release.yml publish job + root `overrides.npm` | the npm CLI doing trusted publishing | bump together, exact |
| actionlint `version: 1.7.10` | actionlint.yml | the linter engine inside the pinned action (defaults to `latest` otherwise) | bump deliberately |
| zizmor engine | zizmor-action (SHA-pinned) | digest-pins its own engine — no extra pin needed | follows action SHA |
| GitHub SSH host keys | release.yml "Configure Git for SSH" | pinned `known_hosts` for the deploy-key push channel (no TOFU keyscan) | re-verify against https://api.github.com/meta if GitHub rotates |

**Bump procedure** (quarterly, or when upstream publishes something we
need): pick the new upstream commit SHA / version, update the pin with a
dated comment, and run the affected workflow via `workflow_dispatch` on
your branch before merging. For the Go-module pins, edit the `require`
line, run `go mod tidy` inside that module directory, and commit both
`go.mod` and `go.sum`. If a new vector legitimately fails, fix the
implementation or document why the vector does not apply — never bump past
a failure silently.

**Do not bump** `GO_QRLLIB_DILITHIUM5_PIN` (`b2ee4790…` = **v0.8.0**, the
last go-qrllib release containing `crypto/dilithium` — upstream removed it
in **v0.9.0**, commit `1ae1760`), `PQCRYSTALS_DILITHIUM5_PIN`
(`ac743d5…`, Round 3), or the `dilithium5-go/go.mod` pseudo-version: these
are permanently historical references for the frozen Dilithium5 scheme.

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
refuses to start over a bloated corpus; `--clean-corpus` purges it.

**Verdict contract.** Every finding class maps to a severity through one
shared map (`scripts/fuzz/engine/verdict.mjs`); harnesses route findings
through a `Verdict` and exit via `verdict.exitCode()` — never bespoke exit
logic. Campaign exit codes:

- **0** clean · **1** interesting (unexpected throw, timeout, canon-drift) ·
  **≥2** critical (false-accept, forgery, malleability, junk return, parser
  non-determinism, src↔dist divergence, sanity-check failure, contract
  violation).
- A child that **dies by signal** (OOM SIGKILL / SIGSEGV, `code === null`)
  is treated as **≥2**, never clamped to clean — that crash class is exactly
  what fuzzing exists to surface. The runner also kills and marks ≥2 any
  child silent past `--watchdog-idle-min` (default 10 min) — a genuine hang.
- Runner-level refusals live **outside** the finding namespace so they can't
  be confused with findings: corpus-guard refusal exits **78** (EX_CONFIG),
  contradictory flags exit **64** (EX_USAGE).

`node scripts/fuzz/test/fault-injection.test.mjs` (a CI gate) injects one
fault of each class and asserts the campaign exit code and `summary.json`
verdict — it locks the wiring above, which no clean campaign ever exercises.
`--profile` and `--iterations` are mutually exclusive (the former names an
iteration budget; passing both is rejected rather than silently overridden).

## Browser & packaging test strategy

Two layers, deliberately paired (house playbook §7):

- **Source-level browser execution.** The full vector suite runs in Chromium
  via Playwright (`packages/*/browser-tests/`, `npm run test:browser`),
  importing the actual `test/*.test.js` files. This proves the source works
  in a real browser engine, not just Node.
- **Published-artifact packaging.** `test/dist-bundle.test.js` (in
  `npm test`) imports the built `dist/{mjs,cjs}` artifacts in subprocesses
  (ESM `import` + CJS `require` + round-trip), and the release pipeline's
  smoke job (`scripts/release/smoke-tarballs.js`) installs the **packed
  `.tgz` bytes** — the same artifact handed to `publish`, never a rebuild —
  into throwaway CJS and ESM projects on a different Node major. So the
  thing tested is literally the thing shipped.

**Rev-4 bundler matrix — waived this cycle (revisit trigger below).** The
js-qrl-cryptography pattern compiles the vector suite under Parcel, webpack,
and Rollup in Chromium to catch bundler-specific exports-map/resolution/
polyfill breakage. For qrypto.js the marginal coverage does not yet justify
the cost:

- Rollup compatibility is already proven — Rollup *is* the build tool that
  produces `dist/{mjs,cjs}`, and the dist-bundle + tarball smoke exercise
  its output and the `exports` map directly.
- The source already executes in a real browser engine (Chromium/Playwright
  above); what the matrix adds over that is Parcel/webpack-specific
  resolution, which this pure-JS package (single runtime dep,
  `@noble/hashes`, no Node-builtin polyfill surface) is far less exposed to
  than a TS-sourced, AES/KDF-bearing library.
- Adopting Parcel + webpack pulls in hundreds of transitive devDependencies,
  in direct tension with §3.5 (minimal dependency surface, `npm audit` 0
  including dev) and would have to be duplicated across both monorepo
  packages.

**Revisit and adopt the matrix if any of these become true:** a consumer
reports a Parcel/webpack-only breakage; the runtime dependency surface grows
beyond `@noble/hashes`; or the package starts relying on Node builtins that
need browser polyfills. Adopting means mirroring js-qrl-cryptography
(`scripts/build-browser-tests.sh` + the three bundlers behind exact pins)
and pairing it with the existing tarball smoke, not replacing it.

**Other rev-4 patterns — noted as not adopted (optional for monorepos):**

- *Reusable `workflow_call` CI* (one job-list consumed by push/PR/release):
  the house guidance scopes this to single-package repos; qrypto.js keeps
  separate workflows because it has specialized verification legs
  (`acvp`/`wycheproof`/`cross-verify`) a single shared battery would not fit
  cleanly. The preflight job re-runs lint/typecheck/check-shared/test/build
  so the release path is still gated on the same checks.
- *Per-module Codecov `components`*: qrypto.js already gets per-package drift
  visibility from monorepo **flags** (`mldsa87` / `dilithium5`), so the
  single-package components pattern adds nothing here.

## Coverage policy

Coverage is **100% — statements, branches, functions, lines — on both
packages**, enforced by the Codecov targets in `codecov.yml`. "Can't reach
100%" is treated as a design smell, not an excuse: if a branch is
unreachable (or has no deterministic trigger), exclude it at the source
with a `/* c8 ignore */` marker and an **adjacent comment explaining why
it cannot be exercised**. The exclusions flow into the lcov upload, so
Codecov and the local `npm run coverage` measure the same 100%.

The point of holding the number at exactly 100% is **drift visibility**:
against a flat-100% baseline, any regression is unmissable and points
directly at the new untested branch — which is why unreachable lines are
excluded (with rationale) rather than letting the number sit below the
ceiling. This repo is past the 100% milestone and the gate is locked in:
**lowering it is a maintainer decision**, made as an explicit, reviewed
change to `codecov.yml` with its reasoning in the PR description — never
a silently failing status or a target edit buried in an unrelated diff.

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
`src/index.d.ts` types the full surface. Only the **documented API** — the
symbols in the README "API Reference": `cryptoSignKeypair`, `cryptoSign`,
`cryptoSignSignature`, `cryptoSignVerify`, `cryptoSignOpen`,
`cryptoSignOpenWithReason`, the deterministic wrappers
(`cryptoSignDeterministic`, `cryptoSignSignatureDeterministic`), the
byte-size constants, and `zeroize`/`isZero` — is the stable contract.
Everything else is exported for testing/interop, is marked `@deprecated`
in the `.d.ts` as internal, and **will move behind a subpath or disappear
at the next major version**. `zeroizePolyVec` is among the deprecated set:
it operates on internal `PolyVecK`/`PolyVecL` types that cannot be
constructed through the documented surface, so it is not part of the stable
contract. Don't grow the internal surface: new helpers that aren't part of
the documented API should not be added to the README or relied upon
downstream. The consumer-compile gate (`npm run typecheck`,
`test/types/*-consumer.mts`) imports every documented symbol from the
package `exports`, so this list and the shipped typings cannot silently
drift apart.

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
