# Security Considerations

This document describes security considerations for using qrypto.js, including JavaScript-specific limitations and best practices.

## Overview

qrypto.js implements post-quantum digital signature algorithms (Dilithium5 and ML-DSA-87). While the cryptographic algorithms are secure, JavaScript/Node.js environments have inherent limitations that affect how secret key material can be handled.

## JavaScript Memory Security Limitations

### No Guaranteed Secure Zeroization

JavaScript does not provide:

1. **Direct memory access** - Cannot guarantee memory is overwritten at a specific location
2. **Compiler barrier semantics** - JIT compilers may optimize away "dead store" writes
3. **Control over garbage collection** - Memory may persist until GC runs (non-deterministic)
4. **Protection against memory swapping** - Secrets may be written to disk swap space

### TypedArray Limitations

Even with `Uint8Array.fill(0)`:

- The operation may be optimized away by the JIT compiler if the array is not used afterward
- Previous values may remain in memory until the garbage collector reclaims the buffer
- The JavaScript runtime may have copied the data internally (e.g., during Buffer operations)

### Buffer Behavior (Node.js)

- `Buffer.alloc()` initializes memory to zero but doesn't prevent later exposure
- `Buffer.allocUnsafe()` may contain previous memory contents
- Buffer pooling may cause memory reuse across different operations

### String Immutability

Converting secret key data to/from strings creates copies that:
- Cannot be overwritten (strings are immutable in JavaScript)
- May be interned or cached by the runtime
- Persist until garbage collected

## What qrypto.js Does

Despite these limitations, qrypto.js implements defense-in-depth measures:

### 1. Uses Uint8Array for Secrets

All secret key material is stored in `Uint8Array` buffers, not strings. This allows:
- Explicit zeroing (even if not guaranteed to be secure)
- Avoiding string interning
- Clearer intent about data sensitivity

### 2. Constant-Time Comparison

Signature verification uses constant-time comparison to prevent timing attacks:

```javascript
// From cryptoSignVerify:
let diff = 0;
for (i = 0; i < length; ++i) {
  diff |= a[i] ^ b[i];
}
return diff === 0;
```

### Timing Considerations for Signing

**Signing is not constant-time.** The `cryptoSignSignature()` path exhibits measurable timing variability across different secret keys, even when signing the same fixed message. This is not a bug in the implementation — it is an inherent property of the Dilithium/ML-DSA algorithm, which uses rejection sampling during signing.

#### Sources of timing variability

1. **Rejection sampling loop** (dominant source): The signing function contains a `while (true)` loop that generates candidate signatures and rejects those that would leak information about the secret key. The number of iterations before a valid signature is found depends on the secret key's internal structure (the s1, s2, and t0 polynomials). Different keys produce different rejection rates at the norm checks on z, w0, and the hint vector. This is by design — the rejection sampling is what makes the signature zero-knowledge — but it means signing time is inherently key-dependent.

2. **JavaScript arithmetic** (secondary source): The Montgomery reduction and other arithmetic operations use JavaScript number types. The JavaScript specification does not guarantee that these operations are constant-time, and execution time may vary based on operand values.

#### Measured impact

Under controlled local measurement using `process.hrtime.bigint()` with deterministic seed-derived keypairs, warmup runs, and fixed 32-byte messages:

- **ML-DSA-87**: Cross-key median signing time ranged from ~4.9 ms to ~34.4 ms (~7x spread)
- **Dilithium5**: Cross-key median signing time ranged from ~4.9 ms to ~23.1 ms (~4.7x spread)

The effect persists under round-robin measurement ordering with retained raw samples, ruling out simple benchmark-order artifacts. A timing regression harness is available at `scripts/timing-sign.mjs`.

#### What this means for deployments

- **Signature verification is constant-time** (see above) — this issue affects signing only
- An attacker with repeated signing access and high-resolution timing may be able to distinguish keys or infer information about the secret key's rejection behavior
- Practical impact depends on deployment context: local or same-host observers are more plausible than network-only observers, where jitter typically drowns out the signal
- No practical key-recovery exploit has been demonstrated from this timing signal

#### Mitigations for sensitive deployments

- For applications with strict constant-time requirements, use the Go implementation ([go-qrllib](https://github.com/theQRL/go-qrllib)) which provides better timing guarantees through constant-time arithmetic primitives
- Rate-limit signing operations at the application layer to reduce timing attack feasibility
- Run signing operations in isolated environments where timing cannot be observed by adversaries
- Use randomized (hedged) signing to add per-signature randomness, which increases same-key timing variance and makes cross-key correlation harder
- Do not expose a signing oracle directly to untrusted users without authentication and rate limiting

### 3. Input Validation

All cryptographic functions validate input lengths and types to prevent:
- Buffer overflow/underflow issues
- Type confusion attacks
- Invalid parameter combinations

### 4. Zeroize Utility (Best Effort)

The `zeroize()` function is provided for clearing sensitive buffers:

```javascript
import { zeroize, cryptoSignKeypair, cryptoSign } from '@theqrl/mldsa87';

const sk = new Uint8Array(CryptoSecretKeyBytes);
const seed = cryptoSignKeypair(null, pk, sk);

// Use the secret key...
const signature = cryptoSign(message, sk, true, ctx);

// Clear when done (best effort) — including the returned seed:
// it is SECRET-KEY-EQUIVALENT (anyone holding it can regenerate the
// full keypair), so treat it with exactly the same care as sk.
zeroize(sk);
zeroize(seed);
```

**Important**: Due to JavaScript limitations, this is a best-effort operation. There is no guarantee that:
- The memory is actually zeroed (JIT optimization)
- Copies don't exist elsewhere (GC, Buffer pooling)
- The data wasn't swapped to disk

## Recommendations

### For Application Developers

1. **Minimize secret lifetime** - Generate keys only when needed, zero them as soon as possible
2. **Treat key-generation seeds as secret keys** - `cryptoSignKeypair()` returns the seed it used; that seed deterministically regenerates the entire keypair. Store it with the same care as `sk` and `zeroize()` it when no longer needed
3. **Avoid serialization** - Don't convert secrets to strings, JSON, or other formats
4. **Don't log secrets** - Never log, print, or transmit secret key material
5. **Use secure storage** - For persistent keys, consider:
   - Hardware Security Modules (HSMs)
   - Operating system keychains
   - Encrypted storage with proper key management
5. **Consider WebCrypto** - For browser environments, WebCrypto provides non-extractable keys

### For High-Security Applications

If your threat model requires strong memory protection:

1. **Use native implementations** - Consider go-qrllib or C implementations that provide better memory control
2. **Use HSMs** - Hardware Security Modules provide the strongest protection
3. **Isolate processes** - Run cryptographic operations in isolated processes/containers
4. **Disable swap** - On systems handling secrets, consider disabling swap or using encrypted swap

## Algorithm Security

### Dilithium5 (Round 3)

- NIST PQC Round 3 finalist
- Security level: Category 5 (equivalent to AES-256)
- Key sizes: PK=2592, SK=4896, Sig=4595 bytes
- Cross-verified against pq-crystals reference (`ac743d5`)

### ML-DSA-87 (FIPS 204)

- NIST FIPS 204 standardized algorithm
- Security level: Category 5 (equivalent to AES-256)
- Key sizes: PK=2592, SK=4896, Sig=4627 bytes
- Includes context parameter for domain separation
- Cross-verified against pq-crystals reference (latest)
- Verified against NIST ACVP keyGen + sigGen vectors (`.github/workflows/acvp.yml`)
- Verified against C2SP/wycheproof verify vectors (`.github/workflows/wycheproof.yml`)

### Signing Modes (ML-DSA-87 and Dilithium5)

Both `cryptoSignSignature` (detached) and `cryptoSign` (attached) take an explicit `randomizedSigning: boolean` parameter:

- **`randomizedSigning: true` (hedged) — recommended.** Per FIPS 204 §3.4, the per-signature nonce is mixed with fresh randomness from the system RNG (`crypto.getRandomValues`) on every call. Two signs over the same `(sk, ctx, message)` produce **distinct** signature bytes; both verify under the same public key. Hedged signing frustrates the fault-injection attack class against deterministic signing where an adversary who can flip a single bit during the `z` computation can differentiate two signatures of the same message and recover `s1`/`s2` by lattice differential analysis. Hardware wallets, cloud signers on untrusted silicon, and any deployment with a plausible fault-model should prefer hedged signing. (TOB-QRLLIB-6.)

- **`randomizedSigning: false` (deterministic, FIPS 204 §3.5) — opt-in.** The per-signature nonce is derived deterministically from the secret key and message, so the same `(sk, ctx, message)` always yields byte-identical signatures. **Use only when the deterministic property is itself a security or protocol requirement** — for example, RANDAO-style verifiable beacon contributions where each validator must produce the same signature for the same input, ACVP / KAT vector reproduction, or deterministic-test fixtures.

For the deterministic opt-in case, prefer the named convenience helpers:

- `cryptoSignSignatureDeterministic(sig, m, sk, ctx)` — detached, deterministic.
- `cryptoSignDeterministic(msg, sk, ctx)` — attached, deterministic.

Both are thin wrappers around the boolean-form API that signal caller intent at the type-system level rather than via a positional bool flag. Verification is unchanged regardless of signing mode — hedged and deterministic signatures verify under the same public key.

## Reporting Security Issues

If you discover a security vulnerability in qrypto.js:

1. **Do not** open a public GitHub issue
2. Report it privately via [GitHub Private Vulnerability Reporting](https://github.com/theQRL/qrypto.js/security/advisories/new) (preferred), or email [security@theqrl.org](mailto:security@theqrl.org)
3. Provide detailed reproduction steps
4. Allow reasonable time for a fix before public disclosure

---

## Bundled Dependencies in the CJS Artifact

Each published package ships two builds:

- **ESM** (`dist/mjs/*.js`) resolves `@noble/hashes` from `node_modules`
  as a normal dependency.
- **CJS** (`dist/cjs/*.js`) **embeds a compiled copy** of `@noble/hashes`
  in the bundle. This is forced by `@noble/hashes` being ESM-only — a CJS
  `require()` cannot load it un-bundled.

Implications for auditors and dependency scanners:

- Tools that scan your application's `node_modules` or lockfile see the
  `@noble/hashes` version used by the **ESM** build. The CJS bundle contains
  the dependency code that was current when this package version was built;
  it is not visible to `npm audit` in consuming applications.
- CJS consumers receive `@noble/hashes` security fixes only via a new
  `@theqrl/mldsa87` / `@theqrl/dilithium5` release, not via transitive
  updates.
- The chain extends one hop further: `@theqrl/wallet.js`'s CJS build embeds
  this package in turn. A `@noble/hashes` fix therefore reaches wallet.js
  CJS consumers only after **both** a qrypto.js release **and** a wallet.js
  release.

**Dependency-patch playbook (maintainers):** when `@noble/hashes` publishes
a security fix, treat it as release-blocking: bump the dependency in both
packages, run `npm run build` to regenerate `dist/`, and land it as a `fix:`
commit so semantic-release publishes promptly. CI's `dist-check` job enforces
that a dependency bump cannot merge without the rebuilt bundles — merging the
bump is sufficient to guarantee the patched CJS artifacts ship with the
resulting release. Then notify wallet.js maintainers to repeat the same
playbook downstream.

---

## Supply Chain Security

### npm Provenance

All npm packages are published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements), which cryptographically links published packages to their source repository and build workflow.

Verify provenance on npm:
```bash
npm audit signatures
```

### Sigstore Attestations

All releases include GitHub attestations backed by Sigstore:
- **Build provenance** for checksums and package files
- **SBOM attestations** in SPDX and CycloneDX formats
- **SLSA Level 3 provenance** for build verification

### Dependency Tracking

Each release includes Software Bill of Materials (SBOM) files:
- `sbom-spdx.json` - SPDX format
- `sbom-cyclonedx.json` - CycloneDX format

---

## Release Verification

All releases include cryptographic attestations and checksums for verification.

### Verifying with GitHub CLI

```bash
# Verify attestations for package files
gh attestation verify package.json --owner theQRL
gh attestation verify package-lock.json --owner theQRL

# Verify SBOM attestation
gh attestation verify sbom-spdx.json --owner theQRL
```

### Verifying Checksums

Download and verify checksums from the release:

```bash
# Download checksums file
curl -LO https://github.com/theQRL/qrypto.js/releases/download/vX.Y.Z/checksums-sha256.txt

# Verify package files
sha256sum -c checksums-sha256.txt
```

### Verifying SLSA Provenance

```bash
# Install slsa-verifier: https://github.com/slsa-framework/slsa-verifier#installation

# Download provenance
curl -LO https://github.com/theQRL/qrypto.js/releases/download/vX.Y.Z/provenance.intoto.jsonl

# Verify provenance
slsa-verifier verify-artifact package.json \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theQRL/qrypto.js
```

### Software Bill of Materials (SBOM)

Each release includes SBOMs in two formats:
- **SPDX**: `sbom-spdx.json`
- **CycloneDX**: `sbom-cyclonedx.json`

These can be analyzed with tools like:
```bash
# Using grype for vulnerability scanning
grype sbom:sbom-spdx.json

# Using syft for inspection
syft convert sbom-cyclonedx.json -o table
```

### What Gets Attested

| Artifact | Attestation Type | Purpose |
|----------|-----------------|---------|
| `package.json`, `package-lock.json` | Build provenance | Verify package dependencies |
| `checksums-sha256.txt` | Build provenance | Integrity verification |
| `sbom-spdx.json` | SBOM | Software composition |
| `sbom-cyclonedx.json` | SBOM | Software composition |
| Source code | SLSA provenance | Build reproducibility |
| npm package | npm provenance | Package authenticity |

### Trust Model

Attestations are signed using GitHub's Sigstore integration:
- **Identity**: GitHub Actions OIDC token
- **Transparency**: Logged in Sigstore's Rekor transparency log
- **Verification**: Proves release came from official CI workflow

---

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [pq-crystals Dilithium](https://github.com/pq-crystals/dilithium)
- [go-qrllib](https://github.com/theQRL/go-qrllib)
