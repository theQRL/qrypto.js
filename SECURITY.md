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

### 3. Input Validation

All cryptographic functions validate input lengths and types to prevent:
- Buffer overflow/underflow issues
- Type confusion attacks
- Invalid parameter combinations

### 4. Zeroize Utility (Best Effort)

The `zeroize()` function is provided for clearing sensitive buffers:

```javascript
import { zeroize } from '@aspect-build/qrypto-common';

const sk = new Uint8Array(CryptoSecretKeyBytes);
cryptoSignKeypair(seed, pk, sk);

// Use the secret key...
const signature = cryptoSign(message, sk);

// Clear when done (best effort)
zeroize(sk);
```

**Important**: Due to JavaScript limitations, this is a best-effort operation. There is no guarantee that:
- The memory is actually zeroed (JIT optimization)
- Copies don't exist elsewhere (GC, Buffer pooling)
- The data wasn't swapped to disk

## Recommendations

### For Application Developers

1. **Minimize secret lifetime** - Generate keys only when needed, zero them as soon as possible
2. **Avoid serialization** - Don't convert secrets to strings, JSON, or other formats
3. **Don't log secrets** - Never log, print, or transmit secret key material
4. **Use secure storage** - For persistent keys, consider:
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

## Reporting Security Issues

If you discover a security vulnerability in qrypto.js:

1. **Do not** open a public GitHub issue
2. Contact the QRL security team privately
3. Provide detailed reproduction steps
4. Allow reasonable time for a fix before public disclosure

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [pq-crystals Dilithium](https://github.com/pq-crystals/dilithium)
- [go-qrllib](https://github.com/theQRL/go-qrllib)
