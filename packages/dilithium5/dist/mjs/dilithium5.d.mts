/**
 * TypeScript definitions for @theqrl/dilithium5
 * Dilithium-5 post-quantum digital signature scheme
 */

// Constants
export const Shake128Rate: number;
export const Shake256Rate: number;
export const Stream128BlockBytes: number;
export const Stream256BlockBytes: number;
export const SeedBytes: number;
export const CRHBytes: number;
export const TRBytes: number;
export const N: number;
export const Q: number;
export const QInv: number;
export const D: number;
export const K: number;
export const L: number;
export const ETA: number;
export const TAU: number;
export const BETA: number;
export const GAMMA1: number;
export const GAMMA2: number;
export const OMEGA: number;
export const PolyT1PackedBytes: number;
export const PolyT0PackedBytes: number;
export const PolyETAPackedBytes: number;
export const PolyZPackedBytes: number;
export const PolyVecHPackedBytes: number;
export const PolyW1PackedBytes: number;
export const CryptoPublicKeyBytes: number;
export const CryptoSecretKeyBytes: number;
export const CryptoBytes: number;
export const PolyUniformNBlocks: number;
export const PolyUniformETANBlocks: number;
export const PolyUniformGamma1NBlocks: number;
export const zetas: readonly number[];

// Core signing functions

/**
 * Generate a Dilithium-5 key pair
 * @param seed - Optional 32-byte seed for deterministic key generation (null for random)
 * @param pk - Output buffer for public key (must be CryptoPublicKeyBytes length)
 * @param sk - Output buffer for secret key (must be CryptoSecretKeyBytes length)
 * @returns The seed used for key generation. **Secret-key-equivalent**: anyone
 *   holding it can regenerate the full keypair — store it with the same care
 *   as `sk` and `zeroize()` it when no longer needed.
 * @throws Error if pk/sk buffers are wrong size or null
 */
export function cryptoSignKeypair(
  seed: Uint8Array | null | undefined,
  pk: Uint8Array,
  sk: Uint8Array
): Uint8Array;

/**
 * Create a signature for a message
 * @param sig - Output buffer for signature (must be CryptoBytes length minimum)
 * @param m - Message to sign (hex string or Uint8Array; strings are parsed as hex only)
 * @param sk - Secret key
 * @param randomizedSigning - If true, use random nonce; if false, deterministic
 * @returns 0 on success
 * @throws Error if sk is wrong size
 */
export function cryptoSignSignature(
  sig: Uint8Array,
  m: Uint8Array | string,
  sk: Uint8Array,
  randomizedSigning: boolean
): number;

/**
 * Sign a message, returning signature concatenated with message
 * @param msg - Message to sign
 * @param sk - Secret key
 * @param randomizedSigning - If true, use random nonce; if false, deterministic
 * @returns Signed message (signature || message)
 * @throws Error if signing fails
 */
export function cryptoSign(
  msg: Uint8Array | string,
  sk: Uint8Array,
  randomizedSigning: boolean
): Uint8Array;

/**
 * Create a deterministic Dilithium5 detached signature
 * (`randomizedSigning = false` wrapper for `cryptoSignSignature`).
 *
 * **Use only when the deterministic property is itself a requirement**.
 * For general-purpose signing prefer `cryptoSignSignature` with
 * `randomizedSigning = true` (hedged — TOB-QRLLIB-6).
 */
export function cryptoSignSignatureDeterministic(
  sig: Uint8Array,
  m: Uint8Array | string,
  sk: Uint8Array
): number;

/**
 * Attached-form deterministic Dilithium5 signing
 * (`randomizedSigning = false` wrapper for `cryptoSign`).
 * Same recommendation as `cryptoSignSignatureDeterministic`.
 * (TOB-QRLLIB-6.)
 */
export function cryptoSignDeterministic(
  msg: Uint8Array | string,
  sk: Uint8Array
): Uint8Array;

/**
 * Verify a signature
 * @param sig - Signature to verify
 * @param m - Message that was signed (hex string or Uint8Array; strings are parsed as hex only)
 * @param pk - Public key
 * @returns true if signature is valid, false otherwise
 */
export function cryptoSignVerify(
  sig: Uint8Array,
  m: Uint8Array | string,
  pk: Uint8Array
): boolean;

/**
 * Open a signed message (verify and extract message)
 * @param sm - Signed message (signature || message)
 * @param pk - Public key
 * @returns Message if valid, undefined if verification fails (or if
 *   sm is null / undefined / non-Uint8Array / shorter than
 *   CryptoBytes — see `cryptoSignOpenWithReason` for distinct
 *   failure-mode reporting)
 */
export function cryptoSignOpen(
  sm: Uint8Array,
  pk: Uint8Array
): Uint8Array | undefined;

/**
 * Failure-mode discriminator returned by `cryptoSignOpenWithReason`.
 * (TOB-QRLLIB-14: distinct failure modes for Open.)
 */
export type CryptoSignOpenReason =
  | 'invalid-sm-type'
  | 'invalid-sm-length'
  | 'invalid-pk'
  | 'verification-failed';

/**
 * Open a signed message with a typed failure-mode report.
 * (TOB-QRLLIB-14.) Behavioural twin of `cryptoSignOpen` that
 * distinguishes API-shape problems (input wrong type / length /
 * shape) from genuine verification failures.
 *
 * `cryptoSignOpen` is kept unchanged and continues to return
 * `undefined` for any failure mode. Use this variant when you need
 * to log or route on specific failure modes.
 *
 * @param sm - Signed message (signature || message)
 * @param pk - Public key
 */
export function cryptoSignOpenWithReason(
  sm: Uint8Array,
  pk: Uint8Array
):
  | { ok: true; message: Uint8Array }
  | { ok: false; reason: CryptoSignOpenReason };

// Utility functions

/**
 * Zero out a buffer (best-effort, see SECURITY.md for limitations)
 * @param buffer - Buffer to zero
 * @throws TypeError if buffer is not Uint8Array
 */
export function zeroize(buffer: Uint8Array): void;

/**
 * Check if buffer is all zeros using constant-time comparison
 * @param buffer - Buffer to check
 * @returns true if all bytes are zero
 * @throws TypeError if buffer is not Uint8Array
 */
export function isZero(buffer: Uint8Array): boolean;

/**
 * Zero the coefficient arrays of a polynomial vector (best-effort, see
 * SECURITY.md). Centralizes the secret-wiping pattern used by signing paths.
 *
 * @deprecated Internal API — its parameter types (`PolyVecK`/`PolyVecL`) are
 * themselves internal and cannot be constructed through the documented
 * surface, so this is a stable function over deprecated types. Not part of
 * the stable documented API; will move behind a subpath or be removed at the
 * next major version. See CONTRIBUTING.md "Public API surface policy".
 */
export function zeroizePolyVec(polyVec: PolyVecK | PolyVecL): void;

// Internal classes (exported but primarily for internal use)

/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export class Poly {
  coeffs: Int32Array;
  constructor();
  copy(poly: Poly): void;
}

/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export class PolyVecK {
  vec: Poly[];
  constructor();
}

/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export class PolyVecL {
  vec: Poly[];
  constructor();
  copy(polyVecL: PolyVecL): void;
}

/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export class KeccakState {
  constructor();
}

// Internal functions (exported but primarily for internal use)
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyNTT(a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyInvNTTToMont(a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyChallenge(c: Poly, seed: Uint8Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function ntt(a: Int32Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function invNTTToMont(a: Int32Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function montgomeryReduce(a: bigint): bigint;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function reduce32(a: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function cAddQ(a: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function decompose(a0: Int32Array, i: number, a: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function power2round(a0: Int32Array, i: number, a: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function makeHint(a0: number, a1: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function useHint(a: number, hint: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function packPk(pk: Uint8Array, rho: Uint8Array, t1: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function packSk(
  sk: Uint8Array,
  rho: Uint8Array,
  tr: Uint8Array,
  key: Uint8Array,
  t0: PolyVecK,
  s1: PolyVecL,
  s2: PolyVecK
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function packSig(
  sig: Uint8Array,
  c: Uint8Array,
  z: PolyVecL,
  h: PolyVecK
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function unpackPk(rho: Uint8Array, t1: PolyVecK, pk: Uint8Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function unpackSk(
  rho: Uint8Array,
  tr: Uint8Array,
  key: Uint8Array,
  t0: PolyVecK,
  s1: PolyVecL,
  s2: PolyVecK,
  sk: Uint8Array
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function unpackSig(
  c: Uint8Array,
  z: PolyVecL,
  h: PolyVecK,
  sig: Uint8Array
): number;

// FIPS 202 SHAKE primitives (low-level XOF interface, primarily internal)
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake128Init(state: KeccakState): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake128Absorb(state: KeccakState, input: Uint8Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake128Finalize(state: KeccakState): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake128SqueezeBlocks(
  out: Uint8Array,
  outputOffset: number,
  nBlocks: number,
  state: KeccakState
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake256Init(state: KeccakState): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake256Absorb(state: KeccakState, input: Uint8Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake256Finalize(state: KeccakState): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function shake256SqueezeBlocks(
  out: Uint8Array,
  outputOffset: number,
  nBlocks: number,
  state: KeccakState
): void;

// Dilithium-specific stream initializers
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function dilithiumShake128StreamInit(
  state: KeccakState,
  seed: Uint8Array,
  nonce: number
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function dilithiumShake256StreamInit(
  state: KeccakState,
  seed: Uint8Array,
  nonce: number
): void;

// Polynomial operations (internal)
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyReduce(a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyCAddQ(a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyAdd(c: Poly, a: Poly, b: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polySub(c: Poly, a: Poly, b: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyShiftL(a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyPointWiseMontgomery(c: Poly, a: Poly, b: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyPower2round(a1: Poly, a0: Poly, a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyDecompose(a1: Poly, a0: Poly, a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyMakeHint(h: Poly, a0: Poly, a1: Poly): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyUseHint(b: Poly, a: Poly, h: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyChkNorm(a: Poly, b: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function rejUniform(
  a: Int32Array,
  aOffset: number,
  len: number,
  buf: Uint8Array,
  bufLen: number
): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyUniform(a: Poly, seed: Uint8Array, nonce: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function rejEta(
  a: Int32Array,
  aOffset: number,
  len: number,
  buf: Uint8Array,
  bufLen: number
): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyUniformEta(a: Poly, seed: Uint8Array, nonce: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyZUnpack(r: Poly, a: Uint8Array, aOffset: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyUniformGamma1(a: Poly, seed: Uint8Array, nonce: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyEtaPack(r: Uint8Array, rOffset: number, a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyEtaUnpack(r: Poly, a: Uint8Array, aOffset: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyT1Pack(r: Uint8Array, rOffset: number, a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyT1Unpack(r: Poly, a: Uint8Array, aOffset: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyT0Pack(r: Uint8Array, rOffset: number, a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyT0Unpack(r: Poly, a: Uint8Array, aOffset: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyZPack(r: Uint8Array, rOffset: number, a: Poly): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyW1Pack(r: Uint8Array, rOffset: number, a: Poly): void;

// Polynomial vector operations (internal)
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecMatrixExpand(mat: PolyVecL[], rho: Uint8Array): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecMatrixPointWiseMontgomery(
  t: PolyVecK,
  mat: PolyVecL[],
  v: PolyVecL
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLUniformEta(v: PolyVecL, seed: Uint8Array, nonce: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLUniformGamma1(v: PolyVecL, seed: Uint8Array, nonce: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLReduce(v: PolyVecL): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLAdd(w: PolyVecL, u: PolyVecL, v: PolyVecL): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLNTT(v: PolyVecL): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLInvNTTToMont(v: PolyVecL): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLPointWisePolyMontgomery(
  r: PolyVecL,
  a: Poly,
  v: PolyVecL
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLPointWiseAccMontgomery(
  w: Poly,
  u: PolyVecL,
  v: PolyVecL
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecLChkNorm(v: PolyVecL, bound: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKUniformEta(v: PolyVecK, seed: Uint8Array, nonce: number): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKReduce(v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKCAddQ(v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKAdd(w: PolyVecK, u: PolyVecK, v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKSub(w: PolyVecK, u: PolyVecK, v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKShiftL(v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKNTT(v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKInvNTTToMont(v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKPointWisePolyMontgomery(
  r: PolyVecK,
  a: Poly,
  v: PolyVecK
): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKChkNorm(v: PolyVecK, bound: number): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKPower2round(v1: PolyVecK, v0: PolyVecK, v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKDecompose(v1: PolyVecK, v0: PolyVecK, v: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKMakeHint(h: PolyVecK, v0: PolyVecK, v1: PolyVecK): number;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKUseHint(w: PolyVecK, u: PolyVecK, h: PolyVecK): void;
/** @deprecated Internal API — not part of the stable documented surface; will move behind a subpath or be removed at the next major version. See CONTRIBUTING.md "Public API surface policy". */
export function polyVecKPackW1(r: Uint8Array, w1: PolyVecK): void;
