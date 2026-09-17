import { shake256 } from '@noble/hashes/sha3.js';
import { hexToBytes as nobleHexToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from './random.js';

import {
  PolyVecK,
  polyVecKAdd,
  polyVecKCAddQ,
  polyVecKChkNorm,
  polyVecKDecompose,
  polyVecKInvNTTToMont,
  polyVecKMakeHint,
  polyVecKNTT,
  polyVecKPackW1,
  polyVecKPointWisePolyMontgomery,
  polyVecKPower2round,
  polyVecKReduce,
  polyVecKShiftL,
  polyVecKSub,
  polyVecKUniformEta,
  polyVecKUseHint,
  PolyVecL,
  polyVecLAdd,
  polyVecLChkNorm,
  polyVecLInvNTTToMont,
  polyVecLNTT,
  polyVecLPointWisePolyMontgomery,
  polyVecLReduce,
  polyVecLUniformEta,
  polyVecLUniformGamma1,
  polyVecMatrixExpand,
  polyVecMatrixPointWiseMontgomery,
} from './polyvec.js';
import {
  BETA,
  CRHBytes,
  TRBytes,
  RNDBytes,
  CTILDEBytes,
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  D,
  ETA,
  GAMMA1,
  GAMMA2,
  K,
  L,
  N,
  OMEGA,
  PolyETAPackedBytes,
  PolyT1PackedBytes,
  PolyW1PackedBytes,
  Q,
  SeedBytes,
} from './const.js';
import { Poly, polyChallenge, polyEtaUnpack, polyNTT, polyT1Unpack } from './poly.js';
import { packPk, packSig, packSk, unpackPk, unpackSig, unpackSk } from './packing.js';
import { zeroize, zeroizePolyVec } from './utils.js';

/**
 * Convert hex string to Uint8Array with strict validation.
 *
 * Accepts an optional 0x/0X prefix. Leading/trailing whitespace is rejected.
 * Empty strings and whitespace-only strings are rejected.
 *
 * @param {string} hex - Hex string (optional 0x prefix, even length, no whitespace).
 * @returns {Uint8Array} Decoded bytes.
 * @throws {Error} If input is not a valid hex string
 * @private
 */
function hexToBytes(hex) {
  // Unreachable via the public API: messageToBytes routes only strings here.
  // Kept as defense-in-depth for any future direct internal caller.
  /* c8 ignore start */
  if (typeof hex !== 'string') {
    throw new Error('message must be a hex string');
  }
  /* c8 ignore stop */
  if (hex !== hex.trim()) {
    throw new Error('hex string must not have leading or trailing whitespace');
  }
  let clean = hex;
  if (clean.startsWith('0x') || clean.startsWith('0X')) {
    clean = clean.slice(2);
  }
  if (clean.length === 0) {
    throw new Error('hex string must not be empty');
  }
  if (clean.length % 2 !== 0) {
    throw new Error('hex string must have an even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('hex string contains non-hex characters');
  }
  return nobleHexToBytes(clean);
}

/**
 * Convert a message to Uint8Array.
 *
 * @param {string|Uint8Array} message - Message as hex string (optional 0x prefix) or Uint8Array.
 * @returns {Uint8Array} Message bytes.
 * @throws {Error} If message is not a Uint8Array or valid hex string
 * @private
 */
function messageToBytes(message) {
  if (typeof message === 'string') {
    return hexToBytes(message);
  }
  if (message instanceof Uint8Array) {
    return message;
  }
  throw new Error('message must be Uint8Array or hex string');
}

/**
 * Generate an ML-DSA-87 key pair.
 *
 * Key generation follows FIPS 204, using domain separator [K, L] during
 * seed expansion to ensure algorithm binding.
 *
 * @param {Uint8Array|null} [passedSeed=null] - Optional 32-byte seed for deterministic key generation.
 *   Pass null or undefined for random key generation.
 * @param {Uint8Array} pk - Output buffer for public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} sk - Output buffer for secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @returns {Uint8Array} The seed used for key generation (useful when passedSeed is null).
 *   **The returned seed is secret-key-equivalent**: anyone holding it can
 *   regenerate the full keypair. Store it with the same care as `sk` and
 *   `zeroize()` it as soon as it is no longer needed.
 * @throws {Error} If pk/sk buffers are null or wrong size, or if seed is wrong size
 *
 * @example
 * const pk = new Uint8Array(CryptoPublicKeyBytes);
 * const sk = new Uint8Array(CryptoSecretKeyBytes);
 * const seed = cryptoSignKeypair(null, pk, sk);
 * // ... persist or use seed (it can regenerate sk!) ...
 * zeroize(seed);
 */
export function cryptoSignKeypair(passedSeed, pk, sk) {
  try {
    if (pk.length !== CryptoPublicKeyBytes) {
      throw new Error(`invalid pk length ${pk.length} | Expected length ${CryptoPublicKeyBytes}`);
    }
    if (sk.length !== CryptoSecretKeyBytes) {
      throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error(`pk/sk cannot be null`, { cause: e });
    } else {
      throw new Error(`${e.message}`, { cause: e });
    }
  }

  // Validate seed length if provided
  if (passedSeed !== null && passedSeed !== undefined) {
    if (passedSeed.length !== SeedBytes) {
      throw new Error(`invalid seed length ${passedSeed.length} | Expected length ${SeedBytes}`);
    }
  }

  const mat = new Array(K).fill().map(() => new PolyVecL());
  const s1 = new PolyVecL();
  const s2 = new PolyVecK();
  const t1 = new PolyVecK();
  const t0 = new PolyVecK();

  // Expand seed -> rho(32), rhoPrime(64), key(32) with domain sep [K, L]
  const seed = passedSeed || randomBytes(SeedBytes);

  const outputLength = 2 * SeedBytes + CRHBytes;
  const domainSep = new Uint8Array([K, L]);
  const seedBuf = shake256.create({}).update(seed).update(domainSep).xof(outputLength);
  const rho = seedBuf.slice(0, SeedBytes);
  const rhoPrime = seedBuf.slice(SeedBytes, SeedBytes + CRHBytes);
  const key = seedBuf.slice(SeedBytes + CRHBytes);

  let s1hat;
  try {
    // Expand matrix
    polyVecMatrixExpand(mat, rho);

    // Sample short vectors s1 and s2
    polyVecLUniformEta(s1, rhoPrime, 0);
    polyVecKUniformEta(s2, rhoPrime, L);

    // Matrix-vector multiplication
    s1hat = new PolyVecL();
    s1hat.copy(s1);
    polyVecLNTT(s1hat);
    polyVecMatrixPointWiseMontgomery(t1, mat, s1hat);
    polyVecKReduce(t1);
    polyVecKInvNTTToMont(t1);

    // Add error vector s2
    polyVecKAdd(t1, t1, s2);

    // Extract t1 and write public key
    polyVecKCAddQ(t1);
    polyVecKPower2round(t1, t0, t1);
    packPk(pk, rho, t1);

    // Compute tr = SHAKE256(pk) (64 bytes) and write secret key
    const tr = shake256.create({}).update(pk).xof(TRBytes);
    packSk(sk, rho, tr, key, t0, s1, s2);

    return seed;
  } finally {
    zeroize(seedBuf);
    zeroize(rhoPrime);
    zeroize(key);
    zeroizePolyVec(s1);
    zeroizePolyVec(s2);
    if (s1hat) zeroizePolyVec(s1hat);
    zeroizePolyVec(t0);
  }
}

// Bound on the FIPS 204 Algorithm 7 rejection loop. Each attempt is accepted
// with probability about 0.26 (3.85 expected attempts, FIPS 204 Table 2), and
// that probability does not depend on the key as long as s1 and s2 are in
// range, which secretKeyVecsInRange guarantees. The chance that a valid key
// needs more than 1024 attempts is below 0.74^1024 < 2^-440, so the bound
// is not expected to fire in honest use. It exists so that a secret key whose other
// fields are adversarial (a t0 chosen so that most attempts need more than
// OMEGA hints) throws instead of spinning. go-qrllib and rust-qrllib use
// the same bound.
const SIGN_MAX_ATTEMPTS = 1024;

/**
 * Create a detached signature for a message with context.
 *
 * Uses the ML-DSA-87 (FIPS 204) signing algorithm with rejection sampling.
 * The context parameter provides domain separation as required by FIPS 204.
 *
 * # Signing-mode recommendation (TOB-QRLLIB-6)
 *
 * **Hedged signing (`randomizedSigning = true`) is the recommended mode**
 * per FIPS 204 §3.4: the per-signature nonce mixes fresh `crypto.getRandomValues`
 * randomness, which frustrates the fault-injection attack class against
 * deterministic signing where an adversary who can flip a single bit during
 * the `z` computation can differentiate two same-message signatures and
 * recover `s1`/`s2` by lattice differential analysis. Verification is
 * unchanged — hedged and deterministic signatures verify under the same
 * public key.
 *
 * **Use deterministic signing (`randomizedSigning = false`) only when the
 * deterministic property is itself a security or protocol requirement** —
 * e.g. RANDAO-style verifiable beacon contributions where each validator
 * must produce the same signature for the same input, or test-vector
 * reproduction. Consider the [cryptoSignDeterministic] convenience wrapper
 * for those cases.
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - **Recommended: `true` (hedged, FIPS 204 §3.4).**
 *   If true, mix fresh `crypto.getRandomValues` randomness into the
 *   per-signature nonce. If false, use a deterministic nonce derived from
 *   message and key (FIPS 204 §3.5).
 * @param {Uint8Array} ctx - Context string for domain separation (required, max 255 bytes).
 *   Pass an empty Uint8Array for no context.
 * @returns {number} 0 on success
 * @throws {TypeError} If sig is not a Uint8Array or is smaller than CryptoBytes
 * @throws {TypeError} If sk is not a Uint8Array
 * @throws {TypeError} If ctx is not a Uint8Array
 * @throws {TypeError} If randomizedSigning is not a boolean
 * @throws {Error} If ctx exceeds 255 bytes
 * @throws {Error} If sk length does not equal CryptoSecretKeyBytes
 * @throws {Error} If an s1 or s2 coefficient of sk is outside [-ETA, ETA] (see [validateSecretKey])
 * @throws {Error} If no signature is accepted within 1024 attempts (a below-2^-440 event for a key from [cryptoSignKeypair])
 * @throws {Error} If message is not a Uint8Array or valid hex string
 *
 * @example
 * const sig = new Uint8Array(CryptoBytes);
 * const ctx = new Uint8Array([0x01, 0x02]);
 * cryptoSignSignature(sig, message, sk, false, ctx);
 */
export function cryptoSignSignature(sig, m, sk, randomizedSigning, ctx) {
  if (!(sig instanceof Uint8Array) || sig.length < CryptoBytes) {
    throw new TypeError(`sig must be at least ${CryptoBytes} bytes and a Uint8Array`);
  }
  if (!(sk instanceof Uint8Array)) {
    throw new TypeError('sk must be a Uint8Array');
  }
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  if (ctx.length > 255) throw new Error(`invalid context length: ${ctx.length} (max 255)`);
  if (typeof randomizedSigning !== 'boolean') {
    throw new TypeError('randomizedSigning must be a boolean');
  }
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const rho = new Uint8Array(SeedBytes);
  const tr = new Uint8Array(TRBytes);
  const key = new Uint8Array(SeedBytes);
  let rhoPrime = new Uint8Array(CRHBytes);
  let nonce = 0;
  const mat = Array(K)
    .fill()
    .map(() => new PolyVecL());
  const s1 = new PolyVecL();
  const y = new PolyVecL();
  const z = new PolyVecL();
  const t0 = new PolyVecK();
  const s2 = new PolyVecK();
  const w1 = new PolyVecK();
  const w0 = new PolyVecK();
  const h = new PolyVecK();
  const cp = new Poly();

  try {
    unpackSk(rho, tr, key, t0, s1, s2, sk);
    if (!secretKeyVecsInRange(s1, s2)) {
      throw new Error('invalid sk: an s1 or s2 coefficient is outside [-ETA, ETA] (invalid-sk-encoding)');
    }

    // pre = 0x00 || len(ctx) || ctx
    const pre = new Uint8Array(2 + ctx.length);
    pre[0] = 0;
    pre[1] = ctx.length;
    pre.set(ctx, 2);

    const mBytes = messageToBytes(m);

    // mu = SHAKE256(tr || pre || m)
    const mu = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);

    // rhoPrime = SHAKE256(key || rnd || mu)
    const rnd = randomizedSigning ? randomBytes(RNDBytes) : new Uint8Array(RNDBytes);
    rhoPrime = shake256.create({}).update(key).update(rnd).update(mu).xof(CRHBytes);
    zeroize(rnd);

    polyVecMatrixExpand(mat, rho);
    polyVecLNTT(s1);
    polyVecKNTT(s2);
    polyVecKNTT(t0);

    for (let attempt = 0; attempt < SIGN_MAX_ATTEMPTS; ++attempt) {
      polyVecLUniformGamma1(y, rhoPrime, nonce++);
      // Matrix-vector multiplication
      z.copy(y);
      polyVecLNTT(z);
      polyVecMatrixPointWiseMontgomery(w1, mat, z);
      polyVecKReduce(w1);
      polyVecKInvNTTToMont(w1);

      // Decompose w and call the random oracle
      polyVecKCAddQ(w1);
      polyVecKDecompose(w1, w0, w1);
      polyVecKPackW1(sig, w1);

      // ctilde = SHAKE256(mu || w1_packed) (64 bytes)
      const ctilde = shake256
        .create({})
        .update(mu)
        .update(sig.subarray(0, K * PolyW1PackedBytes))
        .xof(CTILDEBytes);

      polyChallenge(cp, ctilde);
      polyNTT(cp);

      // Compute z, reject if it reveals secret
      polyVecLPointWisePolyMontgomery(z, cp, s1);
      polyVecLInvNTTToMont(z);
      polyVecLAdd(z, z, y);
      polyVecLReduce(z);
      if (polyVecLChkNorm(z, GAMMA1 - BETA) !== 0) {
        continue;
      }

      polyVecKPointWisePolyMontgomery(h, cp, s2);
      polyVecKInvNTTToMont(h);
      polyVecKSub(w0, w0, h);
      polyVecKReduce(w0);
      if (polyVecKChkNorm(w0, GAMMA2 - BETA) !== 0) {
        continue;
      }

      polyVecKPointWisePolyMontgomery(h, cp, t0);
      polyVecKInvNTTToMont(h);
      polyVecKReduce(h);
      // Unreachable for any decodable t0: each coefficient of c*t0 is a sum
      // of TAU terms of magnitude at most 2^(D-1), so its norm is at most
      // TAU*2^(D-1) = 245760 < GAMMA2 = 261888. Kept as written in FIPS 204
      // Algorithm 7.
      /* c8 ignore start */
      if (polyVecKChkNorm(h, GAMMA2) !== 0) {
        continue;
      }
      /* c8 ignore stop */

      polyVecKAdd(w0, w0, h);
      const n = polyVecKMakeHint(h, w0, w1);
      if (n > OMEGA) {
        continue;
      }

      packSig(sig, ctilde, z, h);
      return 0;
    }
    /* c8 ignore start */
    // Every attempt was rejected. Not reachable by test: for a generated key
    // this is a below-2^-440 event, and the one field a caller can shape,
    // t0, only raises the hint count to about 100 per attempt against
    // OMEGA = 75, so even then about 1 attempt in 100 is accepted and 1024
    // attempts fail with probability below 2^-10. The bound keeps signing
    // time finite for such a key instead of open-ended.
    throw new Error(`signing failed: no signature accepted within ${SIGN_MAX_ATTEMPTS} attempts`);
    /* c8 ignore stop */
  } finally {
    zeroize(key);
    zeroize(rhoPrime);
    zeroizePolyVec(s1);
    zeroizePolyVec(s2);
    zeroizePolyVec(t0);
    zeroizePolyVec(y);
  }
}

/**
 * Create a **deterministic** ML-DSA-87 detached signature
 * (FIPS 204 §3.5 — `randomizedSigning = false`).
 *
 * Convenience wrapper that hard-wires the deterministic mode so callers
 * who *need* byte-identical signatures for the same `(sk, ctx, message)`
 * — RANDAO-style verifiable beacon contributions, ACVP / KAT vector
 * reproduction, deterministic-test fixtures — get a clearly-named
 * entry point rather than passing a bare boolean.
 *
 * **Use only when the deterministic property is itself a requirement.**
 * For general-purpose signing prefer [cryptoSignSignature] with
 * `randomizedSigning = true` (FIPS 204 §3.4 hedged, the recommended
 * mode). (TOB-QRLLIB-6.)
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes bytes)
 * @param {string|Uint8Array} m - Message to sign
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes bytes)
 * @param {Uint8Array} ctx - Context string for domain separation (required, max 255 bytes)
 * @returns {number} 0 on success
 */
export function cryptoSignSignatureDeterministic(sig, m, sk, ctx) {
  return cryptoSignSignature(sig, m, sk, /* randomizedSigning */ false, ctx);
}

/**
 * Sign a message, returning signature concatenated with message.
 *
 * This is the combined sign operation that produces a "signed message" containing
 * both the signature and the original message (signature || message).
 *
 * @param {string|Uint8Array} msg - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce; if false, deterministic
 * @param {Uint8Array} ctx - Context string for domain separation (required, max 255 bytes).
 * @returns {Uint8Array} Signed message (CryptoBytes + msg.length bytes)
 * @throws {TypeError} If ctx is not a Uint8Array
 * @throws {TypeError} If sk or randomizedSigning fail type validation (see cryptoSignSignature)
 * @throws {Error} If signing fails or message/sk/ctx are invalid
 *
 * @example
 * const signedMsg = cryptoSign(message, sk, false, ctx);
 * // signedMsg contains: signature (4627 bytes) || message
 */
export function cryptoSign(msg, sk, randomizedSigning, ctx) {
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  const msgBytes = messageToBytes(msg);

  // Place the message after the signature area. (The C reference uses a
  // backwards copy because its sm/m buffers may alias; here they never do.)
  const sm = new Uint8Array(CryptoBytes + msgBytes.length);
  sm.set(msgBytes, CryptoBytes);
  const result = cryptoSignSignature(sm, msgBytes, sk, randomizedSigning, ctx);

  // Unreachable: cryptoSignSignature returns 0 or throws — defensive
  // tripwire in case a future change introduces a non-zero failure return.
  /* c8 ignore start */
  if (result !== 0) {
    throw new Error('failed to sign');
  }
  /* c8 ignore stop */
  return sm;
}

/**
 * Attached-form **deterministic** ML-DSA-87 signing
 * (FIPS 204 §3.5 — `randomizedSigning = false`).
 *
 * Convenience wrapper that hard-wires the deterministic mode for the
 * attached `signature || message` form. Same recommendation as
 * [cryptoSignSignatureDeterministic]: use only when determinism is a
 * protocol requirement; for general-purpose signing prefer
 * [cryptoSign] with `randomizedSigning = true` (FIPS 204 §3.4 hedged).
 * (TOB-QRLLIB-6.)
 *
 * @param {string|Uint8Array} msg - Message to sign
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes bytes)
 * @param {Uint8Array} ctx - Context string for domain separation (required, max 255 bytes)
 * @returns {Uint8Array} Signed message (signature || message)
 */
export function cryptoSignDeterministic(msg, sk, ctx) {
  return cryptoSign(msg, sk, /* randomizedSigning */ false, ctx);
}

/**
 * Verify a detached signature with context.
 *
 * Performs constant-time verification to prevent timing side-channel attacks.
 * The context must match the one used during signing.
 *
 * @param {Uint8Array} sig - Signature to verify (must be CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message that was signed (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} ctx - Context string used during signing (required, max 255 bytes).
 * @returns {boolean} true if signature is valid, false otherwise
 * @throws {TypeError} If ctx is not a Uint8Array
 *
 * @example
 * const isValid = cryptoSignVerify(signature, message, pk, ctx);
 * if (!isValid) {
 *   throw new Error('Invalid signature');
 * }
 */
export function cryptoSignVerify(sig, m, pk, ctx) {
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  if (ctx.length > 255) return false;
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(CTILDEBytes);
  const c2 = new Uint8Array(CTILDEBytes);
  const cp = new Poly();
  const mat = new Array(K).fill().map(() => new PolyVecL());
  const z = new PolyVecL();
  const t1 = new PolyVecK();
  const w1 = new PolyVecK();
  const h = new PolyVecK();

  if (!(sig instanceof Uint8Array) || sig.length !== CryptoBytes) {
    return false;
  }
  if (!(pk instanceof Uint8Array) || pk.length !== CryptoPublicKeyBytes) {
    return false;
  }

  unpackPk(rho, t1, pk);
  if (unpackSig(c, z, h, sig)) {
    return false;
  }
  if (polyVecLChkNorm(z, GAMMA1 - BETA)) {
    return false;
  }

  /* Compute mu = SHAKE256(tr || pre || m) with tr = SHAKE256(pk) */
  const tr = shake256.create({}).update(pk).xof(TRBytes);

  const pre = new Uint8Array(2 + ctx.length);
  pre[0] = 0;
  pre[1] = ctx.length;
  pre.set(ctx, 2);

  let mBytes;
  try {
    mBytes = messageToBytes(m);
  } catch {
    return false;
  }
  const muFull = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);
  mu.set(muFull);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  polyChallenge(cp, c);
  polyVecMatrixExpand(mat, rho);

  polyVecLNTT(z);
  polyVecMatrixPointWiseMontgomery(w1, mat, z);

  polyNTT(cp);
  polyVecKShiftL(t1);
  polyVecKNTT(t1);
  polyVecKPointWisePolyMontgomery(t1, cp, t1);

  polyVecKSub(w1, w1, t1);
  polyVecKReduce(w1);
  polyVecKInvNTTToMont(w1);

  /* Reconstruct w1 */
  polyVecKCAddQ(w1);
  polyVecKUseHint(w1, w1, h);
  polyVecKPackW1(buf, w1);

  /* Call random oracle and verify challenge */
  const c2Hash = shake256.create({}).update(mu).update(buf).xof(CTILDEBytes);
  c2.set(c2Hash);

  // Constant-time comparison to prevent timing attacks
  let diff = 0;
  for (i = 0; i < CTILDEBytes; ++i) {
    diff |= c[i] ^ c2[i];
  }
  return diff === 0;
}

/**
 * Open a signed message (verify and extract message).
 *
 * This is the counterpart to cryptoSign(). It verifies the signature and
 * extracts the original message from a signed message.
 *
 * @param {Uint8Array} sm - Signed message (signature || message)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} ctx - Context string used during signing (required, max 255 bytes).
 * @returns {Uint8Array|undefined} The original message if valid, undefined if verification fails
 * @throws {TypeError} If ctx is not a Uint8Array
 *
 * @example
 * const message = cryptoSignOpen(signedMsg, pk, ctx);
 * if (message === undefined) {
 *   throw new Error('Invalid signature');
 * }
 */
export function cryptoSignOpen(sm, pk, ctx) {
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  // Type-guard `sm` so callers passing `null` / `undefined` / non-Uint8Array
  // get a clean `undefined` return rather than a `Cannot read properties of
  // null (reading 'length')` thrown deep in the call chain. Mirrors the
  // existing `pk` / `sig` instanceof checks in `cryptoSignVerify`.
  // (TOB-QRLLIB-11.)
  if (!(sm instanceof Uint8Array) || sm.length < CryptoBytes) {
    return undefined;
  }

  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk, ctx)) {
    return undefined;
  }

  return msg;
}

/**
 * Open a signed message with a typed failure-mode report.
 *
 * Behavioural twin of [cryptoSignOpen], but returns a discriminated
 * union so callers can distinguish between API-shape problems (input
 * was the wrong type / length / shape) and genuine cryptographic
 * verification failures. Use this when you need to log or route on
 * specific failure modes — e.g. an attestation pipeline that wants to
 * alarm on "input shape valid but signature did not verify" but
 * silently reject "input shape was wrong".
 *
 * The legacy [cryptoSignOpen] returns `undefined` for every failure
 * mode and is kept unchanged for backward compatibility. Both helpers
 * call into the same underlying verifier — they only differ in how
 * the failure modes are reported.
 *
 * (TOB-QRLLIB-14: distinct failure modes for Open.)
 *
 * @param {Uint8Array} sm Signed message (signature || message).
 * @param {Uint8Array} pk Public key.
 * @param {Uint8Array} ctx FIPS 204 context (max 255 bytes).
 * @returns {{ok: true, message: Uint8Array} | {ok: false, reason: 'invalid-ctx-type'|'invalid-ctx-length'|'invalid-sm-type'|'invalid-sm-length'|'invalid-pk'|'verification-failed'}}
 */
export function cryptoSignOpenWithReason(sm, pk, ctx) {
  if (!(ctx instanceof Uint8Array)) {
    return { ok: false, reason: 'invalid-ctx-type' };
  }
  if (ctx.length > 255) {
    return { ok: false, reason: 'invalid-ctx-length' };
  }
  if (!(sm instanceof Uint8Array)) {
    return { ok: false, reason: 'invalid-sm-type' };
  }
  if (sm.length < CryptoBytes) {
    return { ok: false, reason: 'invalid-sm-length' };
  }
  if (!(pk instanceof Uint8Array) || pk.length !== CryptoPublicKeyBytes) {
    return { ok: false, reason: 'invalid-pk' };
  }
  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk, ctx)) {
    return { ok: false, reason: 'verification-failed' };
  }
  return { ok: true, message: msg };
}

// Public-key validation bounds, derived from the parameter set.
//
// A t1 coefficient v (10 bits, 0..1023) is "large" when each challenge tap
// moves c*2^D*t1 by more than 3*GAMMA2 under both readings available to an
// attacker: as 2^D*v centered modulo Q, which is small for v near 0 and for
// v near 1023 (2^D*1023 = Q - 1); and as (2^(D+1)*v centered modulo Q)/2,
// which is small for v near 512 because 2^(D+1)*512 = 2^D - 1 (mod Q) and
// c*(1 + x + ... + x^255) always has even coefficients (60 taps of +-1 sum
// to an even number), so the halving is real. 3*GAMMA2 is two HighBits bands
// from zero, beyond what a hint corrects, and the verifier accepts at most
// OMEGA hints, so OMEGA + 1 large coefficients is more than it can repair.
// go-qrllib, rust-qrllib and wallet.js apply the same rule and are tested
// against the same vector file (test/vectors/weak_public_key_vectors.json).
const T1_LARGE_LOW = Math.floor((3 * GAMMA2) / (1 << D)) + 1; // 96
const T1_LARGE_HIGH_BELOW_HALF = Math.floor((Q - 6 * GAMMA2) / (1 << (D + 1))); // 415
const T1_LARGE_LOW_ABOVE_HALF = Math.ceil((Q + 6 * GAMMA2) / (1 << (D + 1))); // 608
const T1_LARGE_HIGH = Math.ceil((Q - 3 * GAMMA2) / (1 << D)) - 1; // 927
const T1_MIN_LARGE = OMEGA + 1; // 76

/**
 * Check a packed ML-DSA-87 public key before verifying with it.
 *
 * A weak key is one under which the verifier accepts a signature anyone can
 * compute from the key alone. Key generation never produces one, and FIPS
 * 204 requires [cryptoSignVerify] and [cryptoSignOpen] to accept it, so the
 * check is separate; call it on keys you receive. The rule (at least 76 of
 * the 2048 t1 coefficients in [96, 415] or [608, 927]) and its derivation
 * are in the package README under "Public Key Validation".
 *
 * Never throws. Type and length problems come back as reasons, and the
 * coefficient scan reads every coefficient regardless of content.
 *
 * @param {unknown} pk - Packed public key candidate (rho || t1)
 * @returns {{ok: true} | {ok: false, reason: 'invalid-pk-type'|'invalid-pk-length'|'weak-public-key'}}
 *
 * @example
 * const check = validatePublicKey(pk);
 * if (!check.ok) {
 *   throw new Error(`rejected public key: ${check.reason}`);
 * }
 * const isValid = cryptoSignVerify(signature, message, pk, ctx);
 */
export function validatePublicKey(pk) {
  if (!(pk instanceof Uint8Array)) {
    return { ok: false, reason: 'invalid-pk-type' };
  }
  if (pk.length !== CryptoPublicKeyBytes) {
    return { ok: false, reason: 'invalid-pk-length' };
  }
  // Only t1 (pk[SeedBytes..]) matters; rho is a matrix seed and any value is
  // fine. Count the large coefficients with a branch-free accumulator: every
  // coefficient is unpacked and tested against both bands, no early exit.
  const t1 = new Poly();
  let large = 0;
  for (let i = 0; i < K; ++i) {
    polyT1Unpack(t1, pk, SeedBytes + i * PolyT1PackedBytes);
    for (let j = 0; j < N; ++j) {
      const v = t1.coeffs[j];
      // (a - b) >>> 31 is 1 exactly when a < b (all operands fit in 31 bits).
      const below = ((T1_LARGE_LOW - 1 - v) >>> 31) & ((v - T1_LARGE_HIGH_BELOW_HALF - 1) >>> 31);
      const above = ((T1_LARGE_LOW_ABOVE_HALF - 1 - v) >>> 31) & ((v - T1_LARGE_HIGH - 1) >>> 31);
      large += below | above;
    }
  }
  if (large < T1_MIN_LARGE) {
    return { ok: false, reason: 'weak-public-key' };
  }
  return { ok: true };
}

// s1 and s2 travel in the packed secret key (rho || K || tr || s1 || s2 || t0)
// as 3-bit fields holding ETA - v, so 0..2*ETA are the only encodings key
// generation writes; 5, 6 and 7 decode to -3, -4 and -5. t0 has no invalid
// encoding (every 13-bit field decodes into the Power2Round range) and rho,
// K and tr are opaque bytes, so this is the whole of what can be checked
// without recomputing the public key. An out-of-range s1 or s2 breaks the
// ||z|| < GAMMA1 - BETA bound the rejection loop relies on, and with it the
// zero-knowledge property of the signature. go-qrllib and rust-qrllib apply
// the same check.
const SECRET_KEY_VECS_OFFSET = 2 * SeedBytes + TRBytes;

/**
 * Report whether every coefficient of s1 and s2 lies in [-ETA, ETA].
 * Branch-free: (v + ETA) | (ETA - v) is negative exactly when v is out of
 * range, and the sign bits are OR-ed so the scan never stops early.
 *
 * @param {PolyVecL} s1
 * @param {PolyVecK} s2
 * @returns {boolean}
 */
function secretKeyVecsInRange(s1, s2) {
  let bad = 0;
  for (let i = 0; i < L; ++i) {
    const { coeffs } = s1.vec[i];
    for (let j = 0; j < N; ++j) {
      const v = coeffs[j];
      bad |= (v + ETA) | (ETA - v);
    }
  }
  for (let i = 0; i < K; ++i) {
    const { coeffs } = s2.vec[i];
    for (let j = 0; j < N; ++j) {
      const v = coeffs[j];
      bad |= (v + ETA) | (ETA - v);
    }
  }
  return bad >= 0;
}

/**
 * Check a packed ML-DSA-87 secret key before signing with it.
 *
 * The check is the one every signing function applies: every coefficient of
 * s1 and s2 must lie in [-ETA, ETA]. Keys from [cryptoSignKeypair] always
 * pass; the 3-bit encodings 5, 6 and 7 never come from key generation and
 * make signing throw. rho, K, tr and t0 are not examined, as they have no
 * invalid encoding. See the package README under "Secret Key Validation".
 *
 * Never throws. Type and length problems come back as reasons, the scan
 * reads every coefficient regardless of content, and the unpacked
 * coefficients are zeroed before returning.
 *
 * @param {unknown} sk - Packed secret key candidate
 * @returns {{ok: true} | {ok: false, reason: 'invalid-sk-type'|'invalid-sk-length'|'invalid-sk-encoding'}}
 *
 * @example
 * const check = validateSecretKey(sk);
 * if (!check.ok) {
 *   throw new Error(`rejected secret key: ${check.reason}`);
 * }
 */
export function validateSecretKey(sk) {
  if (!(sk instanceof Uint8Array)) {
    return { ok: false, reason: 'invalid-sk-type' };
  }
  if (sk.length !== CryptoSecretKeyBytes) {
    return { ok: false, reason: 'invalid-sk-length' };
  }
  const s1 = new PolyVecL();
  const s2 = new PolyVecK();
  try {
    for (let i = 0; i < L; ++i) {
      polyEtaUnpack(s1.vec[i], sk, SECRET_KEY_VECS_OFFSET + i * PolyETAPackedBytes);
    }
    for (let i = 0; i < K; ++i) {
      polyEtaUnpack(s2.vec[i], sk, SECRET_KEY_VECS_OFFSET + (L + i) * PolyETAPackedBytes);
    }
    if (!secretKeyVecsInRange(s1, s2)) {
      return { ok: false, reason: 'invalid-sk-encoding' };
    }
    return { ok: true };
  } finally {
    zeroizePolyVec(s1);
    zeroizePolyVec(s2);
  }
}
