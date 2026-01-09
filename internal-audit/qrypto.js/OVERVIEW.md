# qrypto.js Security Audit Overview

## Project Information

**Repository**: qrypto.js
**Language**: JavaScript (ES Modules)
**Purpose**: Post-quantum digital signature implementations
**Audit Date**: January 2026

## Package Structure

```
qrypto.js/
├── packages/
│   ├── dilithium5/     # CRYSTALS-Dilithium (NIST Round 3)
│   │   ├── src/
│   │   │   ├── const.js      # Constants and parameters
│   │   │   ├── sign.js       # Key generation, signing, verification
│   │   │   ├── packing.js    # Key/signature serialization
│   │   │   ├── poly.js       # Polynomial operations
│   │   │   ├── polyvec.js    # Polynomial vector operations
│   │   │   ├── ntt.js        # Number Theoretic Transform
│   │   │   ├── rounding.js   # Rounding functions
│   │   │   └── utils.js      # Utility functions (zeroize, isZero)
│   │   └── test/
│   │       ├── sign.test.js        # Core signing tests
│   │       ├── kat.test.js         # Known Answer Tests (50 tests)
│   │       ├── cross.test.js       # Cross-implementation tests
│   │       ├── edge-cases.test.js  # Edge case tests (10 tests)
│   │       └── utils.test.js       # Utility function tests
│   │
│   └── mldsa87/        # ML-DSA-87 (NIST FIPS 204)
│       ├── src/
│       │   └── (same structure as dilithium5)
│       └── test/
│           ├── sign.test.js        # Core signing tests
│           ├── kat.test.js         # Known Answer Tests (64 tests)
│           ├── cross.test.js       # Cross-implementation tests
│           ├── edge-cases.test.js  # Edge case tests (11 tests)
│           └── utils.test.js       # Utility function tests
│
├── .github/
│   ├── workflows/
│   │   ├── test.yml          # Test workflow (lint + Node 18/20/22)
│   │   ├── coverage.yml      # Code coverage for both packages
│   │   └── cross-verify.yml  # Cross-implementation verification
│   ├── cross-verify/         # pq-crystals C reference verifiers
│   ├── dependabot.yml        # Dependency update automation
│   └── CODEOWNERS            # Code ownership definitions
│
├── README.md                 # Comprehensive documentation
├── SECURITY.md               # Security considerations
│
└── internal-audit/
    └── qrypto.js/
        ├── OVERVIEW.md           # This file
        ├── SECURITY-ANALYSIS.md  # Detailed security findings
        └── TODO.md               # Audit task tracking
```

## Algorithms Implemented

### dilithium5
- CRYSTALS-Dilithium parameter set 5 (highest security level)
- NIST Round 3 specification
- Security level: NIST Level 5

### mldsa87
- ML-DSA-87 (FIPS 204 standardized version)
- Includes context parameter support
- 64-byte challenge (ctilde) vs 32-byte in dilithium5

## Key Parameters

| Parameter | dilithium5 | mldsa87 |
|-----------|------------|---------|
| K | 8 | 8 |
| L | 7 | 7 |
| ETA | 2 | 2 |
| TAU | 60 | 60 |
| BETA | 120 | 120 |
| GAMMA1 | 2^19 | 2^19 |
| GAMMA2 | (Q-1)/32 | (Q-1)/32 |
| OMEGA | 75 | 75 |
| Public Key | 2592 bytes | 2592 bytes |
| Secret Key | 4896 bytes | 4896 bytes |
| Signature | 4595 bytes | 4627 bytes |

## Audit Summary

### Security Issues

| ID | Severity | Status | Description |
|----|----------|--------|-------------|
| SEC-001 | Medium | Verified | Constant-time comparison correctly implemented |
| SEC-002 | Critical | Fixed | TR_BYTES incorrect size in dilithium5 (32 → 64 bytes) |
| SEC-004 | Medium | Fixed | Missing seed validation in key generation |
| SEC-005 | Medium | Completed | Memory security documentation and zeroize utilities |

### Testing Improvements

| ID | Status | Description |
|----|--------|-------------|
| TST-001 | Completed | Cross-implementation verification with go-qrllib |
| TST-002 | Completed | Known Answer Tests (114 KAT tests) |
| TST-003 | Completed | Direct pq-crystals reference verification |
| TST-004 | Completed | Edge case tests (21 tests) |

### Quality & Infrastructure

| ID | Status | Description |
|----|--------|-------------|
| QUA-001 | Completed | ESLint in CI pipeline |
| QUA-002 | Completed | Node.js test matrix (18/20/22) |
| QUA-003 | Completed | Coverage workflow for both packages |
| QUA-004 | Completed | Added `type: "module"` to package.json |
| INF-001 | Completed | GitHub Actions updated to v6 |
| INF-002 | Completed | Dependabot configuration |
| INF-003 | Completed | CODEOWNERS file |
| CI-001 | Completed | Cross-verification GitHub Action |
| DOC-001 | Completed | Comprehensive README with API reference |
| DOC-002 | Completed | API documentation |

## Test Coverage

- **dilithium5**: 69 tests passing
  - Core signing tests
  - KAT tests (50)
  - Cross-implementation tests
  - Edge case tests (10)
  - Utility tests

- **mldsa87**: 84 tests passing
  - Core signing tests
  - KAT tests (64)
  - Cross-implementation tests
  - Edge case tests (11)
  - Utility tests

**Total: 153 tests passing** after all security fixes, testing improvements, and edge case additions.

## Dependencies

- `randombytes`: Cryptographically secure random number generation
- `sha3`: SHAKE128/SHAKE256 hash functions

## CI/CD Infrastructure

- **Test Workflow**: Runs lint check and tests across Node.js 18.x, 20.x, 22.x
- **Coverage Workflow**: Uploads coverage for both packages to Codecov
- **Cross-Verify Workflow**: Bidirectional verification against go-qrllib and pq-crystals
- **Dependabot**: Automated dependency updates (weekly npm and GitHub Actions)

## Related Projects

- **go-qrllib**: Go implementation (reference for cross-verification)
- **pq-crystals/dilithium**: C reference implementation
  - Round 3 @ `ac743d5` (dilithium5)
  - FIPS 204 @ latest (mldsa87)
- **NIST FIPS 204**: ML-DSA specification
- **CRYSTALS-Dilithium**: Original specification

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.0.0 | 2026-01-09 | Initial audit: Security issues identified and fixed |
| v1.1.0 | 2026-01-09 | Testing improvements: KAT, cross-verification, edge cases |
| v1.2.0 | 2026-01-09 | Quality/Infrastructure: CI improvements, documentation |
