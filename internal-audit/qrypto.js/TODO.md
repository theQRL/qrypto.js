# Actionable Improvements

**Review Version:** v1.5.0
**Date:** 2026-01-09
**Repository:** github.com/theQRL/qrypto.js

This document consolidates all actionable improvements identified during the code review, organized by priority and category.

---

## Priority Legend

| Priority | Meaning | Action |
|----------|---------|--------|
| P0 | Critical | Must fix before production |
| P1 | High | Should fix soon |
| P2 | Medium | Fix when possible |
| P3 | Low | Nice to have |

---

## Security Improvements

### P0 - Critical Security

- [x] **SEC-001**: Verify constant-time comparison in signature verification
  - Location: `packages/*/src/sign.js`
  - Risk: Timing side-channel attacks
  - Resolution: Verified - uses constant-time XOR accumulation
  - Status: Closed

- [x] **SEC-002**: Fix TR_BYTES size (32 → 64 bytes) in dilithium5
  - Location: `packages/dilithium5/src/const.js`, `packing.js`, `sign.js`
  - Risk: Incompatibility with pq-crystals Round 3 reference
  - Resolution: Updated TRBytes to 64, SK size from 4864 to 4896 bytes
  - Status: Closed

### P1 - High Priority Security

- [x] **SEC-004**: Add seed length validation in cryptoSignKeypair
  - Location: `packages/dilithium5/src/sign.js`, `packages/mldsa87/src/sign.js`
  - Risk: Invalid seed could cause undefined behavior
  - Resolution: Added validation for 32-byte seed length
  - Status: Closed

- [x] **SEC-005**: Memory Security
  - Location: All packages
  - Risk: Secret key material persisting in memory
  - Resolution:
    - Created comprehensive `SECURITY.md` documenting JavaScript limitations
    - Implemented `zeroize()` and `isZero()` utility functions
    - Documented that JavaScript cannot guarantee secure zeroization
  - Status: Closed

---

## Testing Improvements

### P1 - High Priority Testing

- [x] **TST-001**: Cross-Implementation Verification
  - Location: `packages/*/test/cross.test.js`
  - Resolution:
    - Created go-qrllib test vector generators
    - Verified key/signature sizes match between implementations
    - Documented seed processing differences
  - Status: Closed

- [x] **TST-002**: Known Answer Tests
  - Location: `packages/*/test/kat.test.js`
  - Resolution:
    - Created comprehensive KAT tests for dilithium5 (50 tests)
    - Created comprehensive KAT tests for mldsa87 (64 tests)
    - Parameter verification, deterministic generation, round-trip tests
  - Status: Closed

- [x] **TST-003**: pq-crystals Direct Cross-Verification
  - Location: `.github/cross-verify/*_ref.c`, `*_pqcrystals.js`
  - Resolution:
    - Created C verifier/signer for Dilithium5 (Round 3 @ ac743d5)
    - Created C verifier/signer for ML-DSA-87 (FIPS 204 @ latest)
    - All bidirectional tests passing locally
  - Status: Closed

### P2 - Medium Priority Testing

- [x] **TST-004**: Additional Test Vectors
  - Location: `packages/*/test/edge-cases.test.js`
  - Resolution:
    - Added edge case tests: empty message, 1MB message, context variations
    - Added tampered signature tests (flipped bits, truncated, all-zero)
    - Added single-byte and binary pattern tests
    - Note: NIST ACVP vectors evaluated but not integrated (see Deferred Items)
  - Status: Closed

---

## CI/CD Improvements

### P1 - High Priority CI

- [x] **CI-001**: Cross-Verification GitHub Action
  - Location: `.github/workflows/cross-verify.yml`
  - Resolution:
    - Created workflow with 4 parallel jobs
    - Dilithium5 ↔ go-qrllib bidirectional verification
    - ML-DSA-87 ↔ go-qrllib bidirectional verification
    - Dilithium5 ↔ pq-crystals bidirectional verification
    - ML-DSA-87 ↔ pq-crystals bidirectional verification
  - Status: Closed

---

## Code Quality Improvements

### P2 - Medium Priority Quality

- [x] **QUA-001**: Add ESLint to CI pipeline
  - Location: `.github/workflows/test.yml`
  - Issue: ESLint config exists but not running in CI
  - Resolution: Added lint job to test.yml, added `lint` script to root package.json
  - Status: Closed

- [x] **QUA-002**: Expand Node.js test matrix
  - Location: `.github/workflows/test.yml`
  - Issue: Only testing Node 18.x
  - Resolution: Added Node 18.x, 20.x, and 22.x to test matrix
  - Status: Closed

- [x] **QUA-003**: Fix coverage workflow for mldsa87
  - Location: `.github/workflows/coverage.yml`
  - Issue: Only uploads dilithium5 coverage, missing mldsa87
  - Resolution: Added separate mldsa87 coverage upload to Codecov
  - Status: Closed

- [x] **QUA-004**: Add `type: "module"` to package.json
  - Location: `package.json`
  - Issue: Node warns about MODULE_TYPELESS_PACKAGE_JSON
  - Resolution: Added `"type": "module"` to root package.json
  - Status: Closed

- [x] **QUA-005**: Browser compatibility - migrate from sha3 to @noble/hashes
  - Location: `packages/*/src/fips202.js`, `packages/*/src/sign.js`, `packages/*/package.json`
  - Issue: `sha3` npm package uses Node.js Buffer API, not browser-compatible
  - Resolution:
    - Replaced `sha3` dependency with `@noble/hashes` (^1.7.1)
    - Rewrote fips202.js as wrapper around @noble/hashes SHAKE functions
    - Migrated sign.js to use `shake256` from @noble/hashes directly
    - All 153 tests passing
  - Status: Closed

---

## Infrastructure Improvements

### P2 - Medium Priority Infrastructure

- [x] **INF-001**: Update GitHub Actions versions
  - Location: `.github/workflows/*.yml`
  - Issue: Using outdated actions (checkout@v3/v4, setup-node@v3/v4, setup-go@v5, codecov@v2)
  - Resolution: Updated all workflows to checkout@v6, setup-node@v6, setup-go@v6, codecov@v5
  - Status: Closed

- [x] **INF-002**: Add Dependabot configuration
  - Location: `.github/dependabot.yml`
  - Resolution: Created dependabot.yml with npm and GitHub Actions update schedules
  - Status: Closed

- [x] **INF-003**: Add CODEOWNERS file
  - Location: `.github/CODEOWNERS`
  - Resolution: Created CODEOWNERS with @theQRL/core, @theQRL/crypto, @theQRL/devops
  - Status: Closed

---

## Documentation Improvements

### P2 - Medium Priority Documentation

- [x] **DOC-001**: Expand README
  - Location: `README.md`
  - Issue: README had incorrect examples using Buffer.from() (not browser-compatible)
  - Resolution:
    - Comprehensive rewrite with browser-compatible examples (TextEncoder/Uint8Array)
    - Fixed signature sizes (Dilithium5: 4595, ML-DSA-87: 4627)
    - Added complete API reference for all functions
    - Documented cryptoSignOpen, cryptoSignSignature, zeroize, isZero
    - Added Browser Usage section, TypeScript section
    - Added constants table with correct sizes
  - Status: Closed

- [x] **DOC-002**: API Documentation
  - Location: `README.md`
  - Resolution:
    - Documented cryptoSignKeypair, cryptoSign, cryptoSignVerify
    - Included parameter descriptions and return values
    - Comparison table between implementations
  - Status: Closed

- [x] **DOC-003**: JSDoc comments for public API
  - Location: `packages/*/src/sign.js`, `packages/*/src/utils.js`
  - Resolution:
    - Added comprehensive JSDoc to all public functions in sign.js
    - Documented parameters, return values, throws, and examples
    - Utils.js already had JSDoc comments
  - Status: Closed

---

## Interoperability Notes

**Dilithium5 Seed Processing Difference:**
- go-qrllib: `seed → SHAKE256(seed)[:32] → cryptoSignKeypair`
- qrypto.js: `seed → SHAKE256(seed)[:128] → (rho, rhoPrime, key)`
- **Resolution**: Use go-qrllib's "hashedSeed" as input to qrypto.js for interoperability

**ML-DSA-87 Seed Processing (Compatible):**
- Both implementations use: `seed → SHAKE256(seed || [K,L]) → (rho, rhoPrime, key)`
- Raw seed produces identical keys in both implementations
- No special handling required for interoperability

**Reference Commits:**
- Dilithium5 (Round 3): `pq-crystals/dilithium@ac743d5`
- ML-DSA-87 (FIPS 204): `pq-crystals/dilithium@latest`

---

## Deferred Items

### NIST ACVP Test Vector Integration - Not Planned

**Decision**: NIST ACVP test vectors will not be integrated at this time.

**Rationale**:

1. **Infrastructure overhead**: ACVP is designed as a protocol for automated validation between implementations and NIST's server. Proper integration requires an ACVP client implementation, custom test harness to parse their specific JSON schema, and handling of multiple test types (KeyGen, SigGen, SigVer with various options).

2. **Vector size**: ACVP vector files are very large (tens of MB of JSON for ML-DSA-87 alone), which would significantly increase repository size and CI run times.

3. **Existing coverage is stronger**: The current test suite provides equivalent or better cryptographic correctness guarantees:
   - **pq-crystals direct verification** (TST-003): Bidirectional testing against the actual C reference implementation - this is the source from which ACVP vectors are derived
   - **go-qrllib cross-verification** (TST-001): Interoperability with the production Go implementation
   - **114 KAT tests** (TST-002): Deterministic round-trip verification
   - **21 edge case tests** (TST-004): Boundary conditions and tampering detection

4. **Use case**: ACVP is primarily valuable for formal NIST CAVP/CMVP certification. If formal certification is required in the future, ACVP integration should be revisited as part of that effort.

**Conclusion**: The pq-crystals reference verification provides stronger assurance than derived test vectors, and the current 153-test suite adequately validates cryptographic correctness.

### Shared Cryptographic Core - Not Planned

**Decision**: Extracting a shared `@theqrl/dilithium-common` package will not be implemented.

**Rationale**:

1. **Dilithium5 is legacy**: The `@theqrl/dilithium5` package exists for backward compatibility with existing QRL infrastructure. It implements the pre-FIPS Round 3 specification.

2. **Future deprecation**: Dilithium5 may be removed in a future version as the ecosystem migrates to ML-DSA-87 (FIPS 204). Creating shared infrastructure for a package that may be deprecated adds unnecessary maintenance burden.

3. **Limited benefit**: While ~6 files are duplicated between packages (ntt.js, reduce.js, rounding.js, fips202.js, utils.js, and parts of const.js), the total code size is small (~600 lines). The duplication is manageable and doesn't significantly impact maintainability.

4. **API differences**: The packages have intentional API differences (context parameter in ML-DSA-87, different signature sizes) that would require abstraction layers, adding complexity without clear benefit.

**Conclusion**: Keep packages independent until dilithium5 deprecation decision is made.

---

## Tracking

| ID | Status | Notes |
|----|--------|-------|
| SEC-001 | ✅ Closed | Verified constant-time comparison |
| SEC-002 | ✅ Closed | Fixed TR_BYTES (32→64), SK size 4864→4896 |
| SEC-004 | ✅ Closed | Added seed length validation |
| SEC-005 | ✅ Closed | Created SECURITY.md, zeroize utilities |
| TST-001 | ✅ Closed | Cross-implementation verification with go-qrllib |
| TST-002 | ✅ Closed | KAT tests (114 tests total) |
| TST-003 | ✅ Closed | Direct pq-crystals cross-verification |
| TST-004 | ✅ Closed | Edge case tests added (21 new tests) |
| CI-001 | ✅ Closed | GitHub Actions cross-verify workflow |
| QUA-001 | ✅ Closed | Added ESLint to CI pipeline |
| QUA-002 | ✅ Closed | Expanded Node.js test matrix (18/20/22) |
| QUA-003 | ✅ Closed | Fixed coverage workflow for mldsa87 |
| QUA-004 | ✅ Closed | Added `type: "module"` to package.json |
| QUA-005 | ✅ Closed | Browser compatibility - migrated sha3 → @noble/hashes |
| INF-001 | ✅ Closed | Updated GitHub Actions versions (v3/v4 → v6) |
| INF-002 | ✅ Closed | Added Dependabot configuration |
| INF-003 | ✅ Closed | Added CODEOWNERS file |
| DOC-001 | ✅ Closed | Comprehensive README with API reference |
| DOC-002 | ✅ Closed | API documentation in README |
| DOC-003 | ✅ Closed | JSDoc comments for public API |

**Summary:** 20 Closed, 0 Open

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.0.0 | 2026-01-09 | Initial audit: SEC-001/002/004/005, TST-001/002/003, CI-001 completed. 132 tests passing. |
| v1.1.0 | 2026-01-09 | QUA-001/002/003/004, INF-001/002/003 completed. Added lint to CI, Node 18/20/22 matrix, mldsa87 coverage, type:module, Actions v6, Dependabot, CODEOWNERS. |
| v1.2.0 | 2026-01-09 | TST-004, DOC-001/002 completed. Added edge case tests (21 new), comprehensive README with API docs. 153 tests passing. All items closed. |
| v1.3.0 | 2026-01-09 | QUA-005 completed. Migrated from sha3 to @noble/hashes for browser compatibility. |
| v1.4.0 | 2026-01-09 | DOC-003 completed. Added JSDoc comments to all public API functions. |
| v1.5.0 | 2026-01-09 | DOC-001 updated. Comprehensive README rewrite with browser-compatible examples, correct sizes, full API docs. |
| v1.6.0 | 2026-01-09 | JS-QUA-001 deferred. Shared crypto core not planned - dilithium5 is legacy and may be removed. |
