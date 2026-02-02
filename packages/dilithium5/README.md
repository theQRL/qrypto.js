# @theqrl/dilithium5

Post-quantum digital signatures using CRYSTALS-Dilithium Round 3.

This package implements the Dilithium5 signature scheme at NIST security level 5 (AES-256 equivalent). It's designed for compatibility with [go-qrllib](https://github.com/theQRL/go-qrllib) and existing QRL infrastructure.

## Installation

```bash
npm install @theqrl/dilithium5
```

## Quick Start

```javascript
import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignOpen,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
} from '@theqrl/dilithium5';

// Generate keypair
const pk = new Uint8Array(CryptoPublicKeyBytes);  // 2592 bytes
const sk = new Uint8Array(CryptoSecretKeyBytes);  // 4896 bytes
cryptoSignKeypair(null, pk, sk);  // null = random seed

// Sign a message
const message = new TextEncoder().encode('Hello, quantum world!');
const signedMessage = cryptoSign(message, sk, false);  // false = deterministic

// Verify and extract
const extracted = cryptoSignOpen(signedMessage, pk);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}
console.log(new TextDecoder().decode(extracted));  // "Hello, quantum world!"
```

## API

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CryptoPublicKeyBytes` | 2592 | Public key size in bytes |
| `CryptoSecretKeyBytes` | 4896 | Secret key size in bytes |
| `CryptoBytes` | 4595 | Signature size in bytes |
| `SeedBytes` | 32 | Seed size for key generation |

### Functions

#### `cryptoSignKeypair(seed, pk, sk)`

Generate a keypair from a seed.

- `seed`: `Uint8Array(32)` or `null` for random
- `pk`: `Uint8Array(2592)` - output buffer for public key
- `sk`: `Uint8Array(4896)` - output buffer for secret key
- Returns: The seed used (useful when `seed` is `null`)

#### `cryptoSign(message, sk, randomized)`

Sign a message (combined mode: returns signature || message).

- `message`: `Uint8Array` or `string` - message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted.
- `sk`: `Uint8Array(4896)` - secret key
- `randomized`: `boolean` - `true` for hedged signing, `false` for deterministic
- Returns: `Uint8Array` containing signature + message

#### `cryptoSignOpen(signedMessage, pk)`

Verify and extract message from signed message.

- `signedMessage`: `Uint8Array` - output from `cryptoSign()`
- `pk`: `Uint8Array(2592)` - public key
- Returns: Original message if valid, `undefined` if verification fails

#### `cryptoSignSignature(sig, message, sk, randomized)`

Create a detached signature.

- `sig`: `Uint8Array(4595)` - output buffer for signature
- `message`: `Uint8Array` or `string` - message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted.
- `sk`: `Uint8Array(4896)` - secret key
- `randomized`: `boolean` - `true` for hedged, `false` for deterministic
- Returns: `0` on success

#### `cryptoSignVerify(sig, message, pk)`

Verify a detached signature.

- `sig`: `Uint8Array(4595)` - signature to verify
- `message`: `Uint8Array` or `string` - original message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted.
- `pk`: `Uint8Array(2592)` - public key
- Returns: `true` if valid, `false` otherwise

**Note:** To sign or verify plain text, convert it to bytes (e.g., `new TextEncoder().encode('Hello')`). String inputs are interpreted as hex only.

#### `zeroize(buffer)`

Zero out sensitive data (best-effort, see security notes).

#### `isZero(buffer)`

Check if buffer is all zeros (constant-time).

## Interoperability with go-qrllib

go-qrllib pre-hashes seeds with SHAKE256 before key generation. To generate matching keys:

```javascript
import { shake256 } from '@noble/hashes/sha3';

// go-qrllib: hashedSeed = SHAKE256(rawSeed)[:32]
const hashedSeed = shake256(rawSeed, { dkLen: 32 });

// Use hashedSeed (not rawSeed) with this library
cryptoSignKeypair(hashedSeed, pk, sk);
```

## Dilithium5 vs ML-DSA-87

| Feature | Dilithium5 | ML-DSA-87 |
|---------|------------|-----------|
| Standard | CRYSTALS Round 3 | FIPS 204 |
| Signature size | 4595 bytes | 4627 bytes |
| Context parameter | Not supported | Supported |
| Use case | go-qrllib compatibility | New implementations |

For new projects, consider using [@theqrl/mldsa87](https://www.npmjs.com/package/@theqrl/mldsa87) which implements the FIPS 204 standard.

## Security

See [SECURITY.md](../../SECURITY.md) for important information about:

- JavaScript memory security limitations
- Constant-time verification
- Secure key handling recommendations

## Requirements

- **Node.js**: 18.20+, 20.x, or 22.x (requires `globalThis.crypto.getRandomValues`)
- **Browsers**: [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and ES2020 (BigInt) -- Chrome 67+, Firefox 68+, Safari 14+, Edge 79+
- Full TypeScript definitions included

## License

MIT

## Links

- [Main documentation](../../README.md)
- [go-qrllib](https://github.com/theQRL/go-qrllib) - Go implementation
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/) - Original specification
- [QRL Website](https://theqrl.org)
