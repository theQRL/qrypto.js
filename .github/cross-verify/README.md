# Cross-Implementation Verification

This directory contains helper files for cross-implementation verification tests run by GitHub Actions.

## Overview

These tests verify that qrypto.js signature implementations are interoperable with:
1. **go-qrllib** - The Go implementation used by QRL
2. **pq-crystals** - The authoritative NIST reference implementation

```
                    qrypto.js
                   /         \
                  ↓           ↓
            go-qrllib    pq-crystals reference
                  ↓           (direct verification)
         pq-crystals reference
```

This provides **direct verification** against the NIST reference, plus **indirect verification** through go-qrllib.

## Tests

### Dilithium5 (Round 3)

- Cross-verifies against: go-qrllib Dilithium5
- Tests bidirectional signature verification
- Key sizes: PK=2592, SK=4896, Sig=4595 bytes

**Seed Processing Note:**
go-qrllib pre-hashes the seed with SHAKE256 before key derivation. For interoperability, qrypto.js uses the hashed seed directly:
- go-qrllib: `seed → SHAKE256(seed)[:32] → cryptoSignKeypair`
- qrypto.js (for interop): `hashedSeed → cryptoSignKeypair`

### ML-DSA-87 (FIPS 204)

- Cross-verifies against: go-qrllib ML-DSA-87
- Tests bidirectional signature verification with context parameter
- Key sizes: PK=2592, SK=4896, Sig=4627 bytes
- Context: "ZOND" (standard QRL context)

**Seed Processing:**
Both implementations use the same seed expansion with `[K, L]` domain separator, so raw seeds produce identical keys. No special handling required.

## Files

### go-qrllib Cross-Verification

| File | Description |
|------|-------------|
| `dilithium5_sign.js` | Generate qrypto.js Dilithium5 signature |
| `dilithium5_verify.js` | Verify go-qrllib Dilithium5 signature with qrypto.js |
| `dilithium5_verify.go` | Verify qrypto.js Dilithium5 signature with go-qrllib |
| `dilithium5_sign_goqrllib.go` | Generate go-qrllib Dilithium5 signature |
| `mldsa87_sign.js` | Generate qrypto.js ML-DSA-87 signature |
| `mldsa87_verify.js` | Verify go-qrllib ML-DSA-87 signature with qrypto.js |
| `mldsa87_verify.go` | Verify qrypto.js ML-DSA-87 signature with go-qrllib |
| `mldsa87_sign_goqrllib.go` | Generate go-qrllib ML-DSA-87 signature |

### pq-crystals Cross-Verification

| File | Description |
|------|-------------|
| `dilithium5_verify_ref.c` | Verify qrypto.js Dilithium5 signature with pq-crystals |
| `dilithium5_sign_ref.c` | Generate pq-crystals Dilithium5 signature |
| `dilithium5_verify_pqcrystals.js` | Verify pq-crystals Dilithium5 signature with qrypto.js |
| `mldsa87_verify_ref.c` | Verify qrypto.js ML-DSA-87 signature with pq-crystals |
| `mldsa87_sign_ref.c` | Generate pq-crystals ML-DSA-87 signature |
| `mldsa87_verify_pqcrystals.js` | Verify pq-crystals ML-DSA-87 signature with qrypto.js |

## Running Locally

### Prerequisites

- Node.js 22.x
- Go 1.25.x (for go-qrllib tests)
- GCC (for pq-crystals tests)

### go-qrllib Tests

#### Dilithium5

```bash
# Clone go-qrllib
git clone https://github.com/theQRL/go-qrllib.git /tmp/go-qrllib

# Install qrypto.js dependencies
npm ci

# Test qrypto.js → go-qrllib
node .github/cross-verify/dilithium5_sign.js
go run .github/cross-verify/dilithium5_verify.go

# Test go-qrllib → qrypto.js
cd /tmp/go-qrllib
go run /path/to/qrypto.js/.github/cross-verify/dilithium5_sign_goqrllib.go
cd /path/to/qrypto.js
node .github/cross-verify/dilithium5_verify.js
```

#### ML-DSA-87

```bash
# Test qrypto.js → go-qrllib
node .github/cross-verify/mldsa87_sign.js
go run .github/cross-verify/mldsa87_verify.go

# Test go-qrllib → qrypto.js
cd /tmp/go-qrllib
go run /path/to/qrypto.js/.github/cross-verify/mldsa87_sign_goqrllib.go
cd /path/to/qrypto.js
node .github/cross-verify/mldsa87_verify.js
```

### pq-crystals Tests

#### Dilithium5 (Round 3)

```bash
# Clone pq-crystals Dilithium Round 3
git clone https://github.com/pq-crystals/dilithium.git /tmp/dilithium-ref
cd /tmp/dilithium-ref && git checkout ac743d5

# Install qrypto.js dependencies
cd /path/to/qrypto.js
npm ci

# Test qrypto.js → pq-crystals
node .github/cross-verify/dilithium5_sign.js
cd /tmp/dilithium-ref/ref
gcc -o /tmp/verify_dilithium5 -DDILITHIUM_MODE=5 \
  /path/to/qrypto.js/.github/cross-verify/dilithium5_verify_ref.c \
  sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
  rounding.c symmetric-shake.c fips202.c randombytes.c -I. -O2
/tmp/verify_dilithium5

# Test pq-crystals → qrypto.js
gcc -o /tmp/sign_dilithium5_ref -DDILITHIUM_MODE=5 \
  /path/to/qrypto.js/.github/cross-verify/dilithium5_sign_ref.c \
  sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
  rounding.c symmetric-shake.c fips202.c randombytes.c -I. -O2
/tmp/sign_dilithium5_ref
cd /path/to/qrypto.js
node .github/cross-verify/dilithium5_verify_pqcrystals.js
```

#### ML-DSA-87 (FIPS 204)

```bash
# Clone pq-crystals Dilithium (latest = FIPS 204)
git clone --depth 1 https://github.com/pq-crystals/dilithium.git /tmp/mldsa-ref

# Test qrypto.js → pq-crystals
cd /path/to/qrypto.js
node .github/cross-verify/mldsa87_sign.js
cd /tmp/mldsa-ref/ref
gcc -o /tmp/verify_mldsa87 -DDILITHIUM_MODE=5 \
  /path/to/qrypto.js/.github/cross-verify/mldsa87_verify_ref.c \
  sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
  rounding.c symmetric-shake.c fips202.c randombytes.c -I. -O2
/tmp/verify_mldsa87

# Test pq-crystals → qrypto.js
gcc -o /tmp/sign_mldsa87_ref -DDILITHIUM_MODE=5 \
  /path/to/qrypto.js/.github/cross-verify/mldsa87_sign_ref.c \
  sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
  rounding.c symmetric-shake.c fips202.c randombytes.c -I. -O2
/tmp/sign_mldsa87_ref
cd /path/to/qrypto.js
node .github/cross-verify/mldsa87_verify_pqcrystals.js
```

## Data Exchange

Tests exchange data via temporary files in `/tmp/`:

| Direction | Files |
|-----------|-------|
| qrypto.js → go-qrllib | `/tmp/qrypto_{algo}_pk.bin`, `_sig.bin`, `_msg.bin` |
| go-qrllib → qrypto.js | `/tmp/goqrllib_{algo}_pk.bin`, `_sig.bin`, `_msg.bin` |
| qrypto.js → pq-crystals | `/tmp/qrypto_{algo}_pk.bin`, `_sig.bin`, `_msg.bin` |
| pq-crystals → qrypto.js | `/tmp/ref_{algo}_pk.bin`, `_sig.bin`, `_msg.bin` |

## Verification Chain

The cross-verification provides **direct verification** against the NIST reference:

1. **qrypto.js ↔ pq-crystals**: Direct verification against NIST reference
2. **qrypto.js ↔ go-qrllib**: Verification against QRL's Go implementation
3. **go-qrllib ↔ pq-crystals**: go-qrllib's own cross-verify workflow

This means signatures produced by qrypto.js are **directly verified** against the authoritative pq-crystals reference implementation.
