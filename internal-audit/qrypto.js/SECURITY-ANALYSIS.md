# qrypto.js Security Analysis

## Overview

This document provides a security analysis of the qrypto.js library, a JavaScript implementation of post-quantum digital signature schemes:

- **dilithium5**: CRYSTALS-Dilithium (NIST Round 3) - parameter set 5
- **mldsa87**: ML-DSA-87 (NIST FIPS 204 standardized version)

## Security Findings

### SEC-001: Constant-Time Comparison [VERIFIED PRESENT]

**Severity**: Medium
**Status**: ✅ Already Implemented

Both packages correctly use constant-time comparison for signature verification to prevent timing side-channel attacks:

```javascript
// packages/dilithium5/src/sign.js:317-322
// packages/mldsa87/src/sign.js:336-341
let diff = 0;
for (i = 0; i < SeedBytes; ++i) {
  diff |= c[i] ^ c2[i];
}
return diff === 0;
```

This pattern ensures the comparison time is independent of where differences occur.

---

### SEC-002: TR_BYTES Incorrect Size [FIXED]

**Severity**: Critical
**Status**: ✅ Fixed

**Description**: The dilithium5 package originally used `SeedBytes` (32 bytes) instead of `TRBytes` (64 bytes) for the TR (public key hash) parameter.

**Impact**: Key size mismatch causing incorrect cryptographic operations:
- Expected SK size: 4896 bytes
- Actual SK size (before fix): 4864 bytes (32 bytes short)

**Files Fixed**:

1. **packages/dilithium5/src/const.js:8**
   ```javascript
   export const TRBytes = 64;  // Was implicitly 32 via SeedBytes usage
   ```

2. **packages/dilithium5/src/packing.js:11,58-61,93-96**
   - Added TRBytes import
   - Changed `packSk` to use TRBytes for TR loop
   - Changed `unpackSk` to use TRBytes for TR loop

3. **packages/dilithium5/src/sign.js:279,285**
   ```javascript
   let outputLength = TRBytes;  // Was SeedBytes
   // ...
   state.update(Buffer.from(mu.slice(0, TRBytes), 'hex'));  // Was SeedBytes
   ```

---

### SEC-003: ML-DSA vs Dilithium Differences [INFORMATIONAL]

**Severity**: Informational
**Status**: ✅ Correctly Implemented

The mldsa87 package correctly implements ML-DSA-87 (FIPS 204) differences from Dilithium:

1. **Domain separation in key generation**:
   - mldsa87: `SHAKE256(seed || [K, L])`
   - dilithium5: `SHAKE256(seed)`

2. **Context parameter in signing/verification**:
   - mldsa87: Includes `pre = 0x00 || len(ctx) || ctx` prefix
   - dilithium5: No context parameter

3. **Signature format**:
   - mldsa87: Uses 64-byte `ctilde` (CTILDEBytes)
   - dilithium5: Uses 32-byte challenge (SeedBytes)

4. **RND parameter for randomized signing**:
   - mldsa87: `rhoPrime = SHAKE256(key || rnd || mu)`
   - dilithium5: Different derivation

---

### SEC-004: Seed Validation Missing [FIXED]

**Severity**: Medium
**Status**: ✅ Fixed

**Description**: The `cryptoSignKeypair` function did not validate the length of user-provided seeds.

**Impact**: Invalid seed lengths could cause undefined behavior or weak key generation.

**Files Fixed**:

1. **packages/dilithium5/src/sign.js:69-74**
   ```javascript
   // Validate seed length if provided
   if (passedSeed !== null && passedSeed !== undefined) {
     if (passedSeed.length !== SeedBytes) {
       throw new Error(`invalid seed length ${passedSeed.length} | Expected length ${SeedBytes}`);
     }
   }
   ```

2. **packages/mldsa87/src/sign.js:73-78**
   (Same validation pattern)

---

## Key Size Summary

### dilithium5 (after fixes)
| Parameter | Size (bytes) |
|-----------|-------------|
| Public Key | 2592 |
| Secret Key | 4896 |
| Signature | 4595 |
| Seed | 32 |
| TR | 64 |

### mldsa87
| Parameter | Size (bytes) |
|-----------|-------------|
| Public Key | 2592 |
| Secret Key | 4896 |
| Signature | 4627 |
| Seed | 32 |
| TR | 64 |
| CTILDE | 64 |

---

## Recommendations

### Completed
- [x] Fix TR_BYTES size in dilithium5 (SEC-002)
- [x] Add seed validation in both packages (SEC-004)
- [x] Regenerate test vectors with corrected implementation
- [x] Cross-implementation verification against go-qrllib (TST-001)
- [x] Cross-implementation verification against pq-crystals (TST-003)
- [x] Add Known Answer Tests (KAT) - 114 tests (TST-002)
- [x] Add edge case tests - 21 additional tests (TST-004)
- [x] Memory security documentation and zeroize utilities (SEC-005)
- [x] Timing attack resistance documented in SECURITY.md

### Future Work
- [ ] Integrate NIST ACVP test vectors when practical
- [ ] Consider WebAssembly implementation for performance-critical paths

---

## Test Results

All tests pass after security fixes and comprehensive test suite:
- dilithium5: 69 passing
- mldsa87: 84 passing
- **Total: 153 tests**

```
npm test
Tasks:    2 successful, 2 total
```
