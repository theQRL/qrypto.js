# @theqrl/mldsa87

Post-quantum digital signatures using ML-DSA-87 (FIPS 204).

This package implements the ML-DSA-87 signature scheme at NIST security level 5 (AES-256 equivalent). It follows the [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) standard and is recommended for new implementations.

## Installation

```bash
npm install @theqrl/mldsa87
```

## Quick Start

```javascript
import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignOpen,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
} from '@theqrl/mldsa87';

// Generate keypair
const pk = new Uint8Array(CryptoPublicKeyBytes);  // 2592 bytes
const sk = new Uint8Array(CryptoSecretKeyBytes);  // 4896 bytes
cryptoSignKeypair(null, pk, sk);  // null = random seed

// Sign a message (uses default "ZOND" context)
const message = new TextEncoder().encode('Hello, quantum world!');
const signedMessage = cryptoSign(message, sk, false);  // false = deterministic

// Verify and extract
const extracted = cryptoSignOpen(signedMessage, pk);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}
console.log(new TextDecoder().decode(extracted));  // "Hello, quantum world!"
```

## Context Parameter

ML-DSA-87 supports a context parameter for domain separation (FIPS 204 feature). This allows the same keypair to be used safely across different applications.

```javascript
// With custom context
const ctx = new TextEncoder().encode('my-app-v1');
const signed = cryptoSign(message, sk, false, ctx);
const extracted = cryptoSignOpen(signed, pk, ctx);

// Context must match for verification
cryptoSignOpen(signed, pk);  // undefined - wrong context (default "ZOND")
cryptoSignOpen(signed, pk, ctx);  // message - correct context
```

The default context is `"ZOND"` (for QRL Zond network compatibility). Context can be 0-255 bytes.

## API

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CryptoPublicKeyBytes` | 2592 | Public key size in bytes |
| `CryptoSecretKeyBytes` | 4896 | Secret key size in bytes |
| `CryptoBytes` | 4627 | Signature size in bytes |
| `SeedBytes` | 32 | Seed size for key generation |

### Functions

#### `cryptoSignKeypair(seed, pk, sk)`

Generate a keypair from a seed.

- `seed`: `Uint8Array(32)` or `null` for random
- `pk`: `Uint8Array(2592)` - output buffer for public key
- `sk`: `Uint8Array(4896)` - output buffer for secret key
- Returns: The seed used (useful when `seed` is `null`)

#### `cryptoSign(message, sk, randomized, context?)`

Sign a message (combined mode: returns signature || message).

- `message`: `Uint8Array` - message to sign
- `sk`: `Uint8Array(4896)` - secret key
- `randomized`: `boolean` - `true` for hedged signing, `false` for deterministic
- `context`: `Uint8Array` (optional) - context string, 0-255 bytes. Default: `"ZOND"`
- Returns: `Uint8Array` containing signature + message

#### `cryptoSignOpen(signedMessage, pk, context?)`

Verify and extract message from signed message.

- `signedMessage`: `Uint8Array` - output from `cryptoSign()`
- `pk`: `Uint8Array(2592)` - public key
- `context`: `Uint8Array` (optional) - must match signing context
- Returns: Original message if valid, `undefined` if verification fails

#### `cryptoSignSignature(sig, message, sk, randomized, context?)`

Create a detached signature.

- `sig`: `Uint8Array(4627)` - output buffer for signature
- `message`: `Uint8Array` - message to sign
- `sk`: `Uint8Array(4896)` - secret key
- `randomized`: `boolean` - `true` for hedged, `false` for deterministic
- `context`: `Uint8Array` (optional) - context string, 0-255 bytes
- Returns: `0` on success

#### `cryptoSignVerify(sig, message, pk, context?)`

Verify a detached signature.

- `sig`: `Uint8Array(4627)` - signature to verify
- `message`: `Uint8Array` - original message
- `pk`: `Uint8Array(2592)` - public key
- `context`: `Uint8Array` (optional) - must match signing context
- Returns: `true` if valid, `false` otherwise

#### `zeroize(buffer)`

Zero out sensitive data (best-effort, see security notes).

#### `isZero(buffer)`

Check if buffer is all zeros (constant-time).

## Interoperability

Both this library and go-qrllib process ML-DSA-87 seeds identically. Raw seeds produce matching keys:

```javascript
// Same seed produces same keys in both implementations
cryptoSignKeypair(seed, pk, sk);
```

Verified against the [pq-crystals reference implementation](https://github.com/pq-crystals/dilithium).

## ML-DSA-87 vs Dilithium5

| Feature | ML-DSA-87 | Dilithium5 |
|---------|-----------|------------|
| Standard | FIPS 204 | CRYSTALS Round 3 |
| Signature size | 4627 bytes | 4595 bytes |
| Context parameter | Supported | Not supported |
| Use case | New implementations | go-qrllib compatibility |

Use [@theqrl/dilithium5](https://www.npmjs.com/package/@theqrl/dilithium5) only if you need compatibility with existing QRL infrastructure.

## Security

See [SECURITY.md](../../SECURITY.md) for important information about:

- JavaScript memory security limitations
- Constant-time verification
- Secure key handling recommendations

## Requirements

- Node.js 18+ or modern browsers with ES2020 support
- Full TypeScript definitions included

## License

MIT

## Links

- [Main documentation](../../README.md)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA specification
- [go-qrllib](https://github.com/theQRL/go-qrllib) - Go implementation
- [QRL Website](https://theqrl.org)
