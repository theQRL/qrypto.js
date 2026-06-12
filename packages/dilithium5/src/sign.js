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
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  GAMMA1,
  GAMMA2,
  K,
  L,
  OMEGA,
  PolyW1PackedBytes,
  SeedBytes,
  TRBytes,
} from './const.js';
import { Poly, polyChallenge, polyNTT } from './poly.js';
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
 * Generate a Dilithium-5 key pair.
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

  // Get randomness for rho, rhoPrime and key
  const seed = passedSeed || randomBytes(SeedBytes);

  const outputLength = 2 * SeedBytes + CRHBytes;
  const seedBuf = shake256.create({}).update(seed).xof(outputLength);
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

    // Compute H(rho, t1) and write secret key
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

/**
 * Create a detached signature for a message.
 *
 * Uses the Dilithium-5 (Round 3) signing algorithm with rejection sampling.
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes = 4595 bytes)
 * @param {string|Uint8Array} m - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce for hedged signing.
 *   If false, use deterministic nonce derived from message and key.
 * @returns {number} 0 on success
 * @throws {TypeError} If sig is not a Uint8Array or is smaller than CryptoBytes
 * @throws {TypeError} If sk is not a Uint8Array
 * @throws {TypeError} If randomizedSigning is not a boolean
 * @throws {Error} If sk length does not equal CryptoSecretKeyBytes
 * @throws {Error} If message is not a Uint8Array or valid hex string
 *
 * @example
 * const sig = new Uint8Array(CryptoBytes);
 * cryptoSignSignature(sig, message, sk, false);
 */
export function cryptoSignSignature(sig, m, sk, randomizedSigning) {
  if (!(sig instanceof Uint8Array) || sig.length < CryptoBytes) {
    throw new TypeError(`sig must be at least ${CryptoBytes} bytes and a Uint8Array`);
  }
  if (!(sk instanceof Uint8Array)) {
    throw new TypeError('sk must be a Uint8Array');
  }
  if (typeof randomizedSigning !== 'boolean') {
    throw new TypeError('randomizedSigning must be a boolean');
  }
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const mBytes = messageToBytes(m);

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

    const mu = shake256.create({}).update(tr).update(mBytes).xof(CRHBytes);

    if (randomizedSigning) {
      // randomBytes already returns a fresh Uint8Array; assign it directly so
      // no unwiped intermediate copy is left behind (rhoPrime is zeroized in
      // the finally block).
      rhoPrime = randomBytes(CRHBytes);
    } else {
      rhoPrime = shake256.create({}).update(key).update(mu).xof(CRHBytes);
    }

    polyVecMatrixExpand(mat, rho);
    polyVecLNTT(s1);
    polyVecKNTT(s2);
    polyVecKNTT(t0);

    while (true) {
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

      const cHash = shake256
        .create({})
        .update(mu)
        .update(sig.subarray(0, K * PolyW1PackedBytes))
        .xof(SeedBytes);
      sig.set(cHash);

      polyChallenge(cp, sig.slice(0, SeedBytes));
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
      // Statistically rare rejection (depends on key/challenge interaction);
      // no deterministic trigger is known, so it is exercised by long fuzz
      // campaigns rather than unit vectors.
      /* c8 ignore start */
      if (polyVecKChkNorm(h, GAMMA2) !== 0) {
        continue;
      }
      /* c8 ignore stop */

      polyVecKAdd(w0, w0, h);
      const n = polyVecKMakeHint(h, w0, w1);
      // Statistically rare rejection — same rationale as the ct0 check above.
      /* c8 ignore start */
      if (n > OMEGA) {
        continue;
      }
      /* c8 ignore stop */

      packSig(sig, sig, z, h);
      return 0;
    }
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
 * Create a **deterministic** Dilithium5 detached signature
 * (`randomizedSigning = false`).
 *
 * Convenience wrapper that hard-wires the deterministic mode so callers
 * who *need* byte-identical signatures for the same `(sk, message)`
 * — KAT vector reproduction, deterministic-test fixtures, RANDAO-style
 * protocols — get a clearly-named entry point rather than passing a
 * bare boolean.
 *
 * **Use only when the deterministic property is itself a requirement.**
 * For general-purpose signing prefer [cryptoSignSignature] with
 * `randomizedSigning = true` (hedged signing — TOB-QRLLIB-6 audit
 * recommendation for parity with the lattice-scheme guidance applied
 * to the Go and Rust ports).
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes bytes)
 * @param {string|Uint8Array} m - Message to sign
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes bytes)
 * @returns {number} 0 on success
 */
export function cryptoSignSignatureDeterministic(sig, m, sk) {
  return cryptoSignSignature(sig, m, sk, /* randomizedSigning */ false);
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
 * @returns {Uint8Array} Signed message (CryptoBytes + msg.length bytes)
 * @throws {TypeError} If sk or randomizedSigning fail type validation (see cryptoSignSignature)
 * @throws {Error} If signing fails or message/sk are invalid
 *
 * @example
 * const signedMsg = cryptoSign(message, sk, false);
 * // signedMsg contains: signature (4595 bytes) || message
 */
export function cryptoSign(msg, sk, randomizedSigning) {
  const msgBytes = messageToBytes(msg);

  // Place the message after the signature area. (The C reference uses a
  // backwards copy because its sm/m buffers may alias; here they never do.)
  const sm = new Uint8Array(CryptoBytes + msgBytes.length);
  sm.set(msgBytes, CryptoBytes);
  const result = cryptoSignSignature(sm, msgBytes, sk, randomizedSigning);

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
 * Attached-form **deterministic** Dilithium5 signing
 * (`randomizedSigning = false`).
 *
 * Convenience wrapper that hard-wires the deterministic mode for the
 * attached `signature || message` form. Same recommendation as
 * [cryptoSignSignatureDeterministic]: use only when determinism is a
 * protocol requirement; for general-purpose signing prefer
 * [cryptoSign] with `randomizedSigning = true` (hedged — TOB-QRLLIB-6).
 *
 * @param {string|Uint8Array} msg - Message to sign
 * @param {Uint8Array} sk - Secret key
 * @returns {Uint8Array} Signed message (signature || message)
 */
export function cryptoSignDeterministic(msg, sk) {
  return cryptoSign(msg, sk, /* randomizedSigning */ false);
}

/**
 * Verify a detached signature.
 *
 * Performs constant-time verification to prevent timing side-channel attacks.
 *
 * @param {Uint8Array} sig - Signature to verify (must be CryptoBytes = 4595 bytes)
 * @param {string|Uint8Array} m - Message that was signed (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @returns {boolean} true if signature is valid, false otherwise
 *
 * @example
 * const isValid = cryptoSignVerify(signature, message, pk);
 * if (!isValid) {
 *   throw new Error('Invalid signature');
 * }
 */
export function cryptoSignVerify(sig, m, pk) {
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(SeedBytes);
  const c2 = new Uint8Array(SeedBytes);
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

  /* Compute CRH(H(rho, t1), msg) */
  const tr = shake256.create({}).update(pk).xof(TRBytes);
  mu.set(tr);

  let mBytes;
  try {
    mBytes = messageToBytes(m);
  } catch {
    return false;
  }
  const muFull = shake256.create({}).update(mu.slice(0, TRBytes)).update(mBytes).xof(CRHBytes);
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
  const c2Hash = shake256.create({}).update(mu).update(buf).xof(SeedBytes);
  c2.set(c2Hash);

  // Constant-time comparison to prevent timing attacks
  let diff = 0;
  for (i = 0; i < SeedBytes; ++i) {
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
 * @returns {Uint8Array|undefined} The original message if valid, undefined if verification fails
 *
 * @example
 * const message = cryptoSignOpen(signedMsg, pk);
 * if (message === undefined) {
 *   throw new Error('Invalid signature');
 * }
 */
export function cryptoSignOpen(sm, pk) {
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
  if (!cryptoSignVerify(sig, msg, pk)) {
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
 * verification failures. See the ML-DSA-87 sibling for the rationale
 * (TOB-QRLLIB-14).
 *
 * @param {Uint8Array} sm Signed message (signature || message).
 * @param {Uint8Array} pk Public key.
 * @returns {{ok: true, message: Uint8Array} | {ok: false, reason: 'invalid-sm-type'|'invalid-sm-length'|'invalid-pk'|'verification-failed'}}
 */
export function cryptoSignOpenWithReason(sm, pk) {
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
  if (!cryptoSignVerify(sig, msg, pk)) {
    return { ok: false, reason: 'verification-failed' };
  }
  return { ok: true, message: msg };
}
