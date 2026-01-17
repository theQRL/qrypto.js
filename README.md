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

// Sign a message (uses default "ZOND" context for "QRL v2.0" applications)
const message = new TextEncoder().encode('Hello, quantum world!');
const signedMessage = cryptoSign(message, sk, false);

// Verify and extract
const extracted = cryptoSignOpen(signedMessage, pk);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}

// With custom context (FIPS 204 feature)
const customContext = new TextEncoder().encode('my-app-v1');
const signedWithCtx = cryptoSign(message, sk, false, customContext);
const extractedWithCtx = cryptoSignOpen(signedWithCtx, pk, customContext);
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
const message = new TextEncoder().encode('Hello, quantum world!');
const signedMessage = cryptoSign(message, sk, false);  // false = deterministic

// Open signed message (verify + extract)
const extracted = cryptoSignOpen(signedMessage, pk);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}
console.log(new TextDecoder().decode(extracted));  // "Hello, quantum world!"

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
| `seed` | `Uint8Array` or `null` | 32-byte seed, or `null` for random |
| `pk` | `Uint8Array` | Output buffer for public key (2592 bytes) |
| `sk` | `Uint8Array` | Output buffer for secret key (4896 bytes) |
| **Returns** | `Uint8Array` | The seed used (useful when `seed` is `null`) |

**Throws:** `Error` if buffers are wrong size or `null`

### Combined Sign/Verify

```javascript
// Sign: returns signature || message
cryptoSign(message, sk, randomized, [context]) → Uint8Array

// Open: verifies and extracts message
cryptoSignOpen(signedMessage, pk, [context]) → Uint8Array | undefined
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `Uint8Array` or `string` | Message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted. |
| `sk` | `Uint8Array` | Secret key (4896 bytes) |
| `randomized` | `boolean` | `true` for hedged signing, `false` for deterministic |
| `context` | `Uint8Array` | (ML-DSA only) Context string, 0-255 bytes. Default: "ZOND" (for "QRL v2.0" applications) |
| `signedMessage` | `Uint8Array` | Output from `cryptoSign()` |
| `pk` | `Uint8Array` | Public key (2592 bytes) |

**Returns:**
- `cryptoSign`: Concatenated signature + message
- `cryptoSignOpen`: Original message if valid, `undefined` if verification fails

### Detached Signatures

```javascript
// Create detached signature
cryptoSignSignature(sig, message, sk, randomized, [context]) → number

// Verify detached signature
cryptoSignVerify(sig, message, pk, [context]) → boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `sig` | `Uint8Array` | Output buffer for signature / signature to verify (>= `CryptoBytes`) |
| `message` | `Uint8Array` or `string` | Message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted. |
| `sk` | `Uint8Array` | Secret key (4896 bytes) |
| `pk` | `Uint8Array` | Public key (2592 bytes) |
| `randomized` | `boolean` | `true` for hedged, `false` for deterministic |
| `context` | `Uint8Array` | (ML-DSA only) Context string, 0-255 bytes |

**Returns:**
- `cryptoSignSignature`: `0` on success
- `cryptoSignVerify`: `true` if valid, `false` otherwise

**Note:** If you need to sign human-readable text, convert it to bytes first (e.g., `new TextEncoder().encode('Hello')`). String inputs are interpreted as hex only.

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
| Context parameter | Required (default: "ZOND" for "QRL v2.0" applications) | Not supported |
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

**Dilithium5:** go-qrllib pre-hashes seeds with SHAKE256 before key generation. To generate matching keys:
```javascript
// In go-qrllib: hashedSeed = SHAKE256(rawSeed)[:32]
// Use hashedSeed (not rawSeed) with qrypto.js
cryptoSignKeypair(hashedSeed, pk, sk);
```

### With pq-crystals Reference

Both implementations are verified against the pq-crystals C reference:
- ML-DSA-87: `pq-crystals/dilithium@latest` (FIPS 204)
- Dilithium5: `pq-crystals/dilithium@ac743d5` (Round 3)

Cross-verification tests run in CI for every commit.

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
  } from 'https://cdn.jsdelivr.net/npm/@theqrl/mldsa87@1.0.4/dist/mjs/mldsa87.js';

  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  cryptoSignKeypair(null, pk, sk);

  const message = new TextEncoder().encode('Hello from browser!');
  const signed = cryptoSign(message, sk, false);
  const verified = cryptoSignOpen(signed, pk);
  console.log('Verified:', verified !== undefined);
</script>
```

## Security Considerations

See [SECURITY.md](./SECURITY.md) for important security information, including:

- **Memory security:** JavaScript cannot guarantee secure zeroization of secret keys
- **Side channels:** Signature verification uses constant-time comparison
- **Randomness:** Uses Web Crypto (`crypto.getRandomValues()`) in browsers and Node 18.20+. If Web Crypto is unavailable in Node, falls back to `crypto.randomBytes()`
- **Key handling:** Recommendations for secure key storage and disposal

## Development

```bash
# Install dependencies
npm install

# Run all tests (153 tests across both packages)
npm test

# Run browser tests (Playwright)
npm run test:browser

# Run linter
npm run lint

# Build distributions
npm run build
```

## Requirements

- Node.js 18.20+, 20.x, or 22.x
- Modern browsers with ES2020 support

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
