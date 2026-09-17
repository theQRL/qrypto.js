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

// Sign a message. The randomized flag is required — there is no default;
// hedged (`true`) is the FIPS 204 §3.4 recommended mode. Pass `false`
// only when deterministic signatures are themselves a protocol
// requirement (e.g. RANDAO-style verifiable beacon contributions); for
// that case use `cryptoSignDeterministic`.
const message = new TextEncoder().encode('Hello, quantum world!');
const ctx = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]);  // "ZOND"
const signedMessage = cryptoSign(message, sk, true, ctx);  // true = hedged (recommended)

// Verify and extract (context must match)
const extracted = cryptoSignOpen(signedMessage, pk, ctx);
if (extracted === undefined) {
  throw new Error('Invalid signature');
}
console.log(new TextDecoder().decode(extracted));  // "Hello, quantum world!"
```

## Context Parameter

ML-DSA-87 requires a context parameter for domain separation (FIPS 204 feature). This allows the same keypair to be used safely across different applications.

```javascript
// With application-specific context
const ctx = new TextEncoder().encode('my-app-v1');
const signed = cryptoSign(message, sk, true, ctx);  // hedged (recommended)
const extracted = cryptoSignOpen(signed, pk, ctx);

// Context must match for verification
const wrongCtx = new Uint8Array(0);
cryptoSignOpen(signed, pk, wrongCtx);  // undefined - wrong context
cryptoSignOpen(signed, pk, ctx);       // message - correct context
```

Context is a required `Uint8Array` and can be 0-255 bytes. Use an empty `Uint8Array(0)` if no domain separation is needed.

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

- `seed`: `Uint8Array(32)`, `null`, or `undefined` for random
- `pk`: `Uint8Array(2592)` - output buffer for public key
- `sk`: `Uint8Array(4896)` - output buffer for secret key
- Returns: The seed used (useful when `seed` is `null`)

#### `cryptoSign(message, sk, randomized, context)`

Sign a message (combined mode: returns signature || message).

- `message`: `Uint8Array` or `string` - message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted.
- `sk`: `Uint8Array(4896)` - secret key
- `randomized`: `boolean` - `true` for hedged signing, `false` for deterministic
- `context`: `Uint8Array` - context string for domain separation, 0-255 bytes
- Returns: `Uint8Array` containing signature + message

#### `cryptoSignOpen(signedMessage, pk, context)`

Verify and extract message from signed message.

- `signedMessage`: `Uint8Array` - output from `cryptoSign()`
- `pk`: `Uint8Array(2592)` - public key
- `context`: `Uint8Array` - must match signing context
- Returns: Original message if valid, `undefined` if verification fails

#### `cryptoSignSignature(sig, message, sk, randomized, context)`

Create a detached signature.

- `sig`: `Uint8Array(4627)` - output buffer for signature
- `message`: `Uint8Array` or `string` - message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted.
- `sk`: `Uint8Array(4896)` - secret key
- `randomized`: `boolean` - `true` for hedged, `false` for deterministic
- `context`: `Uint8Array` - context string for domain separation, 0-255 bytes
- Returns: `0` on success
- Throws: `Error` if `sk` has an s1 or s2 coefficient outside `[-2, 2]` (see [Secret Key Validation](#secret-key-validation)), or if no signature is accepted within 1024 attempts, a below-2^-440 event for a key from `cryptoSignKeypair`

#### `cryptoSignVerify(sig, message, pk, context)`

Verify a detached signature.

- `sig`: `Uint8Array(4627)` - signature to verify
- `message`: `Uint8Array` or `string` - original message bytes; if `string`, it must be hex only (optional `0x`, even length). Plain-text strings are not accepted.
- `pk`: `Uint8Array(2592)` - public key
- `context`: `Uint8Array` - must match signing context
- Returns: `true` if valid, `false` otherwise

**Note:** To sign or verify plain text, convert it to bytes (e.g., `new TextEncoder().encode('Hello')`). String inputs are interpreted as hex only.

#### `validatePublicKey(pk)`

Check a public key before verifying with it. Not part of FIPS 204; see [Public Key Validation](#public-key-validation).

- `pk`: any value
- Returns: `{ ok: true }`, or `{ ok: false, reason }` where `reason` is `'invalid-pk-type'`, `'invalid-pk-length'` or `'weak-public-key'`
- Never throws

#### `validateSecretKey(sk)`

Check a secret key before signing with it. Every signing function runs the same check; see [Secret Key Validation](#secret-key-validation).

- `sk`: any value
- Returns: `{ ok: true }`, or `{ ok: false, reason }` where `reason` is `'invalid-sk-type'`, `'invalid-sk-length'` or `'invalid-sk-encoding'`
- Never throws

#### `zeroize(buffer)`

Zero out sensitive data (best-effort, see security notes).

- `buffer`: `Uint8Array` - the buffer to zero
- Throws: `TypeError` if buffer is not a `Uint8Array`

#### `isZero(buffer)`

Check if buffer is all zeros (constant-time).

- `buffer`: `Uint8Array` - the buffer to check
- Returns: `true` if all bytes are zero
- Throws: `TypeError` if buffer is not a `Uint8Array`

## Public Key Validation

A weak key is a public key under which the verifier accepts a signature
anyone can compute from the key alone. Key generation never produces one,
but a key that arrives from outside can have any shape, so check keys you
receive before verifying with them:

```javascript
import { validatePublicKey, cryptoSignVerify } from '@theqrl/mldsa87';

const check = validatePublicKey(pk); // never throws
if (!check.ok) {
  // reason: 'invalid-pk-type' | 'invalid-pk-length' | 'weak-public-key'
  throw new Error(`rejected public key: ${check.reason}`);
}
const valid = cryptoSignVerify(sig, message, pk, ctx);
```

The rule: a packed key is `rho || t1`, and `t1` holds 2048 coefficients of
10 bits each. A coefficient `v` is large when `96 <= v <= 415` or
`608 <= v <= 927`. The key is weak unless at least 76 of its coefficients
are large. `rho` is not examined.

Where the numbers come from: the verifier recomputes
`w1' = UseHint(h, A·z - c·2^13·t1)` and accepts when hashing `w1'` with the
message reproduces the challenge `c`. With `z = 0` and no hints that value
is `-c·2^13·t1`, so if every coefficient of `c·2^13·t1`, centered modulo
`q = 8380417`, has HighBits zero, the signature
`(z = 0, h = 0, c~ = SHAKE256(mu || w1Encode(0)))` verifies on any message.
Two shapes of `t1` allow that. Small residues: `2^13·v mod q` is small when
`v` is near 0 and also when `v` is near 1023, because `2^13·1023 = q - 1`.
The 2^-1 family: `2^13·512 mod q` equals `2^-1·(2^13 - 1)`, and since the
challenge has 60 coefficients of ±1, `c` times a polynomial of all 512s has
only even coefficients, the 2^-1 cancels, and every product coefficient is
at most `30·8191`, below GAMMA2 = 261888; coefficients from 464 to 559
behave the same way, and 416 to 607 come within reach of hints. A
coefficient counts as large when, under both readings, each challenge tap
moves the result by more than `3·GAMMA2`, two HighBits bands away from
zero and beyond what a hint can repair. That gives
`96 = floor(3·GAMMA2 / 2^13) + 1`, `415 = floor((q - 6·GAMMA2) / 2^14)`,
`608 = ceil((q + 6·GAMMA2) / 2^14)` and
`927 = ceil((q - 3·GAMMA2) / 2^13) - 1`. The verifier accepts at most
OMEGA = 75 hints, so 76 large coefficients is one more than it can
correct. A generated key has about 1280 large coefficients (the expected
fraction is 0.625, and the lowest seen over 500 keys was 1230), so the
chance of rejecting an honest key is below 2^-800.

`cryptoSignVerify` and `cryptoSignOpen` do not apply this check. FIPS 204
Algorithm 8 has no key-validity step, and the C2SP/wycheproof vectors this
package is tested against include `valid` signatures under the all-zero
key (tcId 66 and 174) and under the all-1023 key (tcId 240);
`test/wycheproof.test.js` pins that.
go-qrllib, rust-qrllib and `@theqrl/wallet.js` apply the same rule and are
tested against the same vector file,
`test/vectors/weak_public_key_vectors.json`, so a key is accepted or
rejected on every QRL client alike.

## Secret Key Validation

A packed secret key is `rho || K || tr || s1 || s2 || t0`. The s1 and s2
coefficients are stored as 3-bit fields holding `2 - v`, so 0 to 4 are the
only encodings key generation writes; 5, 6 and 7 decode to -3, -4 and -5.
A coefficient outside `[-2, 2]` breaks the `||z|| < GAMMA1 - BETA` bound
the signing loop relies on, and with it the zero-knowledge property of the
signature, so every signing function checks s1 and s2 after unpacking and
throws on such a key. `validateSecretKey` is the same check ahead of time
and reports `'invalid-sk-encoding'`. `rho`, `K`, `tr` and `t0` have no
invalid encoding and are not examined. Keys from `cryptoSignKeypair`
always pass.

Signing is also bounded to 1024 attempts of the FIPS 204 rejection loop.
A key that passes the check is accepted about once in four attempts, so
for it the bound is a below-2^-440 event; it is there for a `t0` shaped to
demand more than OMEGA hints on most attempts, which then throws instead
of running open-ended. go-qrllib and rust-qrllib apply the same check and
bound.

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
- **Signing timing variability** — signing is not constant-time due to the algorithm's rejection sampling loop; see SECURITY.md for measured impact and deployment mitigations
- Secure key handling recommendations
- **Public key validation:** `cryptoSignVerify` does not reject weak keys, as FIPS 204 requires; check keys you receive with `validatePublicKey` (see above)
- **Secret key validation:** signing throws on an `sk` whose s1 or s2 encoding is out of range; `validateSecretKey` is the same check ahead of time (see above)

## Requirements

- **Node.js**: 20.19+, 22.x, or 24.x (requires `globalThis.crypto.getRandomValues`)
- **Browsers**: [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and ES2020 (BigInt) -- Chrome 67+, Firefox 68+, Safari 14+, Edge 79+
- Full TypeScript definitions included

## License

MIT

## Links

- [Main documentation](../../README.md)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA specification
- [go-qrllib](https://github.com/theQRL/go-qrllib) - Go implementation
- [QRL Website](https://theqrl.org)
