# qrypto.js

[![codecov](https://codecov.io/gh/theQRL/qrypto.js/graph/badge.svg)](https://codecov.io/gh/theQRL/qrypto.js)

Post-quantum cryptographic signature library for JavaScript/TypeScript.

This monorepo contains implementations of quantum-resistant digital signature algorithms for the QRL (Quantum Resistant Ledger) ecosystem. Works in both Node.js and browsers.

## Packages

| Package | Description | Standard | Signature Size | Version |
|---------|-------------|----------|----------------|---------|
| [@theqrl/mldsa87](./packages/mldsa87) | ML-DSA-87 signatures | FIPS 204 (final) | 4627 bytes | [![npm version](https://img.shields.io/npm/v/@theqrl/mldsa87.svg)](https://www.npmjs.com/package/@theqrl/mldsa87) |
| [@theqrl/dilithium5](./packages/dilithium5) | Dilithium5 signatures | CRYSTALS-Dilithium Round 3 | 4595 bytes | [![npm version](https://img.shields.io/npm/v/@theqrl/dilithium5.svg)](https://www.npmjs.com/package/@theqrl/dilithium5) |

## Installation

```bash
# ML-DSA-87 (FIPS 204)
npm install @theqrl/mldsa87

# Dilithium5 (Round 3, pre-FIPS)
npm install @theqrl/dilithium5
```

## Quick Start

### ML-DSA-87 (FIPS 204)

```javascript
import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignOpen,
  cryptoSignVerify,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
} from '@theqrl/mldsa87';

// Generate keypair
const pk = new Uint8Array(CryptoPublicKeyBytes);  // 2592 bytes
const sk = new Uint8Array(CryptoSecretKeyBytes);  // 4896 bytes
cryptoSignKeypair(null, pk, sk);

// Sign a message with context for domain separation (FIPS 204)
const message = new TextEncoder().encode('The sleeper must awaken');
const ctx = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]);  // "ZOND"
const signedMessage = cryptoSign(message, sk, false, ctx);

// Verify and extract (context must match)
const extracted = cryptoSignOpen(signedMessage, pk, ctx);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}
```

> [!NOTE]
> The following section on Dilithium5 is maintained for compatibility with legacy tools and projects. For all new development, ML-DSA-87 is recommended.

### Dilithium5

```javascript
import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignOpen,
  cryptoSignVerify,
  cryptoSignSignature,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
} from '@theqrl/dilithium5';

// Generate keypair
const pk = new Uint8Array(CryptoPublicKeyBytes);  // 2592 bytes
const sk = new Uint8Array(CryptoSecretKeyBytes);  // 4896 bytes
const seed = cryptoSignKeypair(null, pk, sk);     // null = random seed

// Sign a message (browser-compatible)
const message = new TextEncoder().encode('The sleeper must awaken');
const signedMessage = cryptoSign(message, sk, false);  // false = deterministic

// Open signed message (verify + extract)
const extracted = cryptoSignOpen(signedMessage, pk);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}
console.log(new TextDecoder().decode(extracted));  // "The sleeper must awaken"

// Alternative: detached signature verification
const signature = signedMessage.slice(0, CryptoBytes);  // First 4595 bytes
const isValid = cryptoSignVerify(signature, message, pk);
console.log('Signature valid:', isValid);  // true
```

## API Reference

### Constants

| Constant | ML-DSA-87 | Dilithium5 | Description |
|----------|-----------|------------|-------------|
| `CryptoPublicKeyBytes` | 2592 | 2592 | Public key size |
| `CryptoSecretKeyBytes` | 4896 | 4896 | Secret key size |
| `CryptoBytes` | 4627 | 4595 | Signature size |
| `SeedBytes` | 32 | 32 | Seed size for key generation |

### Key Generation

```javascript
cryptoSignKeypair(seed, pk, sk) → Uint8Array
```

Generate a keypair from a seed.

| Parameter | Type | Description |
|-----------|------|-------------|
| `seed` | `Uint8Array`, `null`, or `undefined` | 32-byte seed, or `null`/`undefined` for random |
| `pk` | `Uint8Array` | Output buffer for public key (2592 bytes) |
| `sk` | `Uint8Array` | Output buffer for secret key (4896 bytes) |
| **Returns** | `Uint8Array` | The seed used (useful when `seed` is `null`) |

**Throws:** `Error` if buffers are wrong size or `null`

> [!WARNING]
> The returned seed is **secret-key-equivalent** — anyone holding it can
> regenerate the full keypair. Store it with the same care as `sk` and
> `zeroize()` it as soon as it is no longer needed.

### Combined Sign/Verify

```javascript
// Sign: returns signature || message
cryptoSign(message, sk, randomized, context) → Uint8Array    // ML-DSA-87
cryptoSign(message, sk, randomized) → Uint8Array              // Dilithium5

// Open: verifies and extracts message
cryptoSignOpen(signedMessage, pk, context) → Uint8Array | undefined    // ML-DSA-87
cryptoSignOpen(signedMessage, pk) → Uint8Array | undefined              // Dilithium5
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `Uint8Array` or `string` | Message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted. |
| `sk` | `Uint8Array` | Secret key (4896 bytes) |
| `randomized` | `boolean` | `true` for hedged signing, `false` for deterministic |
| `context` | `Uint8Array` | (ML-DSA-87 only, required) Context string, 0-255 bytes. Use `new Uint8Array(0)` for no context. |
| `signedMessage` | `Uint8Array` | Output from `cryptoSign()` |
| `pk` | `Uint8Array` | Public key (2592 bytes) |

**Returns:**
- `cryptoSign`: Concatenated signature + message
- `cryptoSignOpen`: Original message if valid, `undefined` if verification fails

### Detached Signatures

```javascript
// Create detached signature
cryptoSignSignature(sig, message, sk, randomized, context) → number    // ML-DSA-87
cryptoSignSignature(sig, message, sk, randomized) → number              // Dilithium5

// Verify detached signature
cryptoSignVerify(sig, message, pk, context) → boolean    // ML-DSA-87
cryptoSignVerify(sig, message, pk) → boolean              // Dilithium5
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `sig` | `Uint8Array` | Output buffer for signature (>= `CryptoBytes`); for verify, exactly `CryptoBytes` — any other length returns `false` |
| `message` | `Uint8Array` or `string` | Message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted. |
| `sk` | `Uint8Array` | Secret key (4896 bytes) |
| `pk` | `Uint8Array` | Public key (2592 bytes) |
| `randomized` | `boolean` | `true` for hedged, `false` for deterministic |
| `context` | `Uint8Array` | (ML-DSA-87 only, required) Context string, 0-255 bytes |

**Returns:**
- `cryptoSignSignature`: `0` on success
- `cryptoSignVerify`: `true` if valid, `false` otherwise

**Note:** If you need to sign human-readable text, convert it to bytes first (e.g., `new TextEncoder().encode('Hello')`). String inputs are interpreted as hex only.

### Deterministic Signing (opt-in)

The `randomized` parameter has no default — hedged (`true`) is recommended (FIPS 204 §3.4). When byte-identical signatures are themselves the requirement (RANDAO-style beacon contributions, KAT/ACVP vector reproduction), use the named deterministic wrappers so the choice is explicit at the call site:

```javascript
// Attached, deterministic
cryptoSignDeterministic(message, sk, context) → Uint8Array    // ML-DSA-87
cryptoSignDeterministic(message, sk) → Uint8Array              // Dilithium5

// Detached, deterministic
cryptoSignSignatureDeterministic(sig, message, sk, context) → number    // ML-DSA-87
cryptoSignSignatureDeterministic(sig, message, sk) → number              // Dilithium5
```

These are exactly `cryptoSign` / `cryptoSignSignature` with `randomized = false`; verification is identical for both modes.

### Open With Failure Reason

`cryptoSignOpenWithReason` is a behavioural twin of `cryptoSignOpen` that distinguishes API-shape problems from genuine verification failures, for logging or routing. `cryptoSignOpen` stays total (returns `undefined` for every failure); **never branch security logic on the reason.**

```javascript
cryptoSignOpenWithReason(signedMessage, pk, context)    // ML-DSA-87
cryptoSignOpenWithReason(signedMessage, pk)             // Dilithium5
// → { ok: true,  message: Uint8Array }
// → { ok: false, reason: 'invalid-ctx-type' | 'invalid-ctx-length'
//                       | 'invalid-sm-type' | 'invalid-sm-length'
//                       | 'invalid-pk' | 'verification-failed' }
```

```javascript
const result = cryptoSignOpenWithReason(signedMessage, pk, context);
if (result.ok) {
  use(result.message);
} else {
  log(result.reason); // diagnostics only — not a security signal
}
```

### Security Utilities

```javascript
import { zeroize, isZero } from '@theqrl/mldsa87';

// Zero out sensitive data (best-effort, see SECURITY.md)
zeroize(secretKey);

// Check if buffer is all zeros (constant-time)
if (!isZero(buffer)) {
  console.log('Buffer contains non-zero data');
}
```

**Important:** JavaScript cannot guarantee secure memory zeroization. See [SECURITY.md](./SECURITY.md) for limitations.

## Key Differences

| Feature | ML-DSA-87 | Dilithium5 |
|---------|-----------|------------|
| Standard | FIPS 204 | CRYSTALS Round 3 |
| Signature size | 4627 bytes | 4595 bytes |
| Context parameter | Required (`Uint8Array`, 0-255 bytes) | Not supported |
| Challenge size | 64 bytes | 32 bytes |
| Use case | New implementations | Legacy/go-qrllib compat |

**Which should I use?**
- **ML-DSA-87**: Recommended for new projects. FIPS 204 compliant, will be required for US government use.
- **Dilithium5**: For compatibility with existing applications utilising this scheme.

## Interoperability

### With go-qrllib

**ML-DSA-87:** Both implementations process seeds identically. Raw seeds produce matching keys:
```javascript
// Same seed produces same keys in both implementations
cryptoSignKeypair(seed, pk, sk);
```

**Dilithium5 (historical):** upstream go-qrllib **removed its
`crypto/dilithium` package in v0.9.0** (commit `1ae1760`, 2026-06-10);
**go-qrllib v0.8.0** (commit `b2ee4790`) is the last release containing
it. `@theqrl/dilithium5` is now the maintained implementation of this
scheme in the QRL ecosystem, and CI continues to cross-verify against the
pinned go-qrllib v0.8.0. For interop with go-qrllib ≤ v0.8.0 (or other
tools derived from it): go-qrllib pre-hashed seeds with SHAKE256 before
key generation, so to generate matching keys:
```javascript
// In legacy go-qrllib: hashedSeed = SHAKE256(rawSeed)[:32]
// Use hashedSeed (not rawSeed) with qrypto.js
cryptoSignKeypair(hashedSeed, pk, sk);
```

### With pq-crystals Reference

Both implementations are verified against the pq-crystals C reference:
- ML-DSA-87: `pq-crystals/dilithium` (FIPS 204, pinned commit)
- Dilithium5: `pq-crystals/dilithium@ac743d5` (Round 3)

Cross-verification tests run in CI for every commit, against
commit-pinned copies of go-qrllib and the C reference (see
`.github/workflows/cross-verify.yml` for the exact pins).

## Browser Usage

This library is browser-compatible. It uses native `Uint8Array` throughout (no Node.js `Buffer` dependency).

```html
<script type="module">
  import {
    cryptoSignKeypair,
    cryptoSign,
    cryptoSignOpen,
    CryptoPublicKeyBytes,
    CryptoSecretKeyBytes,
  } from 'https://cdn.jsdelivr.net/npm/@theqrl/mldsa87@2/dist/mjs/mldsa87.js';

  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  cryptoSignKeypair(null, pk, sk);

  const message = new TextEncoder().encode('Hello from browser!');
  const ctx = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]);  // "ZOND"
  const signed = cryptoSign(message, sk, false, ctx);
  const verified = cryptoSignOpen(signed, pk, ctx);
  console.log('Verified:', verified !== undefined);
</script>
```

## Security Considerations

See [SECURITY.md](./SECURITY.md) for important security information, including:

- **Memory security:** JavaScript cannot guarantee secure zeroization of secret keys
- **Side channels:** Signature verification uses constant-time comparison
- **Randomness:** Uses Web Crypto API (`crypto.getRandomValues()`) exclusively. Throws if unavailable. Includes basic entropy validation to detect broken RNG implementations.
- **Key handling:** Recommendations for secure key storage and disposal

## Development

```bash
# Install dependencies
npm install

# Run all tests (450+ tests across both packages)
npm test

# Run browser tests (Playwright)
npm run test:browser

# Run linter
npm run lint

# Build distributions
npm run build
```

## Requirements

- **Node.js**: 20.19+, 22.x, or 24.x (requires `globalThis.crypto.getRandomValues`, available throughout the supported range)
- **Browsers**: Any modern browser with [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) support (`crypto.getRandomValues()`) and ES2020 (BigInt). This includes Chrome 67+, Firefox 68+, Safari 14+, and Edge 79+.
- **Not supported**: Internet Explorer, Node.js < 20, or environments without Web Crypto API

## TypeScript

Full TypeScript definitions are included:

```typescript
import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignVerify,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
} from '@theqrl/mldsa87';

const pk: Uint8Array = new Uint8Array(CryptoPublicKeyBytes);
const sk: Uint8Array = new Uint8Array(CryptoSecretKeyBytes);
cryptoSignKeypair(null, pk, sk);
```

## License

MIT

## Links

- [QRL Website](https://theqrl.org)
- [go-qrllib](https://github.com/theQRL/go-qrllib) - Go implementation
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA specification
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/) - Original specification
