import pkg from 'randombytes';
import { shake256 } from '@noble/hashes/sha3.js';

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
  GAMMA1,
  GAMMA2,
  K,
  L,
  OMEGA,
  PolyW1PackedBytes,
  SeedBytes,
} from './const.js';
import { Poly, polyChallenge, polyNTT } from './poly.js';
import { packPk, packSig, packSk, unpackPk, unpackSig, unpackSk } from './packing.js';

const randomBytes = pkg;

/**
 * Default signing context ("ZOND" in ASCII).
 * Used for domain separation per FIPS 204.
 * @constant {Uint8Array}
 */
const DEFAULT_CTX = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]); // "ZOND"

/**
 * Convert hex string to Uint8Array
 * @param {string} hex - Hex-encoded string
 * @returns {Uint8Array} Decoded bytes
 * @private
 */
function hexToBytes(hex) {
  const len = hex.length / 2;
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return result;
}

/**
 * Generate an ML-DSA-87 key pair.
 *
 * Key generation follows FIPS 204, using domain separator [K, L] during
 * seed expansion to ensure algorithm binding.
 *
 * @param {Uint8Array|null} passedSeed - Optional 32-byte seed for deterministic key generation.
 *   Pass null for random key generation.
 * @param {Uint8Array} pk - Output buffer for public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} sk - Output buffer for secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @returns {Uint8Array} The seed used for key generation (useful when passedSeed is null)
 * @throws {Error} If pk/sk buffers are null or wrong size, or if seed is wrong size
 *
 * @example
 * const pk = new Uint8Array(CryptoPublicKeyBytes);
 * const sk = new Uint8Array(CryptoSecretKeyBytes);
 * const seed = cryptoSignKeypair(null, pk, sk);
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
      throw new Error(`pk/sk cannot be null`);
    } else {
      throw new Error(`${e.message}`);
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

  // Expand matrix
  polyVecMatrixExpand(mat, rho);

  // Sample short vectors s1 and s2
  polyVecLUniformEta(s1, rhoPrime, 0);
  polyVecKUniformEta(s2, rhoPrime, L);

  // Matrix-vector multiplication
  const s1hat = new PolyVecL();
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
}

/**
 * Create a detached signature for a message with optional context.
 *
 * Uses the ML-DSA-87 (FIPS 204) signing algorithm with rejection sampling.
 * The context parameter provides domain separation as required by FIPS 204.
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message to sign (hex string or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce for hedged signing.
 *   If false, use deterministic nonce derived from message and key.
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string for domain separation (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {number} 0 on success
 * @throws {Error} If sk is wrong size or context exceeds 255 bytes
 *
 * @example
 * const sig = new Uint8Array(CryptoBytes);
 * cryptoSignSignature(sig, message, sk, false);
 * // Or with custom context:
 * cryptoSignSignature(sig, message, sk, false, new Uint8Array([0x01, 0x02]));
 */
export function cryptoSignSignature(sig, m, sk, randomizedSigning, ctx = DEFAULT_CTX) {
  if (ctx.length > 255) throw new Error(`invalid context length: ${ctx.length} (max 255)`);
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

  unpackSk(rho, tr, key, t0, s1, s2, sk);

  // pre = 0x00 || len(ctx) || ctx
  const pre = new Uint8Array(2 + ctx.length);
  pre[0] = 0;
  pre[1] = ctx.length;
  pre.set(ctx, 2);

  // Convert hex message to bytes
  const mBytes = typeof m === 'string' ? hexToBytes(m) : m;

  // mu = SHAKE256(tr || pre || m)
  const mu = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);

  // rhoPrime = SHAKE256(key || rnd || mu)
  const rnd = randomizedSigning ? randomBytes(RNDBytes) : new Uint8Array(RNDBytes);
  rhoPrime = shake256.create({}).update(key).update(rnd).update(mu).xof(CRHBytes);

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

    // ctilde = SHAKE256(mu || w1_packed) (64 bytes)
    const ctilde = shake256
      .create({})
      .update(mu)
      .update(sig.slice(0, K * PolyW1PackedBytes))
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
    if (polyVecKChkNorm(h, GAMMA2) !== 0) {
      continue;
    }

    polyVecKAdd(w0, w0, h);
    const n = polyVecKMakeHint(h, w0, w1);
    if (n > OMEGA) {
      continue;
    }

    packSig(sig, ctilde, z, h);
    return 0;
  }
}

/**
 * Sign a message, returning signature concatenated with message.
 *
 * This is the combined sign operation that produces a "signed message" containing
 * both the signature and the original message (signature || message).
 *
 * @param {Uint8Array} msg - Message to sign
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce; if false, deterministic
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string for domain separation (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {Uint8Array} Signed message (CryptoBytes + msg.length bytes)
 * @throws {Error} If signing fails
 *
 * @example
 * const signedMsg = cryptoSign(message, sk, false);
 * // signedMsg contains: signature (4627 bytes) || message
 */
export function cryptoSign(msg, sk, randomizedSigning, ctx = DEFAULT_CTX) {
  const sm = new Uint8Array(CryptoBytes + msg.length);
  const mLen = msg.length;
  for (let i = 0; i < mLen; ++i) {
    sm[CryptoBytes + mLen - 1 - i] = msg[mLen - 1 - i];
  }
  const result = cryptoSignSignature(sm, msg, sk, randomizedSigning, ctx);

  if (result !== 0) {
    throw new Error('failed to sign');
  }
  return sm;
}

/**
 * Verify a detached signature with optional context.
 *
 * Performs constant-time verification to prevent timing side-channel attacks.
 * The context must match the one used during signing.
 *
 * @param {Uint8Array} sig - Signature to verify (must be CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message that was signed (hex string or Uint8Array)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string used during signing (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {boolean} true if signature is valid, false otherwise
 *
 * @example
 * const isValid = cryptoSignVerify(signature, message, pk);
 * if (!isValid) {
 *   throw new Error('Invalid signature');
 * }
 */
export function cryptoSignVerify(sig, m, pk, ctx = DEFAULT_CTX) {
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

  if (sig.length !== CryptoBytes) {
    return false;
  }
  if (pk.length !== CryptoPublicKeyBytes) {
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

  // Convert hex message to bytes
  const mBytes = typeof m === 'string' ? hexToBytes(m) : m;
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
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string used during signing (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {Uint8Array|undefined} The original message if valid, undefined if verification fails
 *
 * @example
 * const message = cryptoSignOpen(signedMsg, pk);
 * if (message === undefined) {
 *   throw new Error('Invalid signature');
 * }
 */
export function cryptoSignOpen(sm, pk, ctx = DEFAULT_CTX) {
  if (sm.length < CryptoBytes) {
    return undefined;
  }

  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk, ctx)) {
    return undefined;
  }

  return msg;
}
