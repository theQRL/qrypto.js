/**
 * TypeScript definitions for @theqrl/mldsa87
 * ML-DSA-87 (FIPS 204) post-quantum digital signature scheme
 */

// Constants
export const Shake128Rate: number;
export const Shake256Rate: number;
export const Stream128BlockBytes: number;
export const Stream256BlockBytes: number;
export const SeedBytes: number;
export const CRHBytes: number;
export const TRBytes: number;
export const RNDBytes: number;
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
export const CTILDEBytes: number;
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
 * Generate an ML-DSA-87 key pair
 * @param seed - Optional 32-byte seed for deterministic key generation (null for random)
 * @param pk - Output buffer for public key (must be CryptoPublicKeyBytes length)
 * @param sk - Output buffer for secret key (must be CryptoSecretKeyBytes length)
 * @returns The seed used for key generation
 * @throws Error if pk/sk buffers are wrong size or null
 */
export function cryptoSignKeypair(
  seed: Uint8Array | null,
  pk: Uint8Array,
  sk: Uint8Array
): Uint8Array;

/**
 * Create a signature for a message
 * @param sig - Output buffer for signature (must be CryptoBytes length minimum)
 * @param m - Message to sign (hex string or Uint8Array; strings are parsed as hex only)
 * @param sk - Secret key
 * @param randomizedSigning - If true, use random nonce; if false, deterministic
 * @param ctx - Context string (max 255 bytes)
 * @returns 0 on success
 * @throws Error if sk is wrong size or context too long
 */
export function cryptoSignSignature(
  sig: Uint8Array,
  m: Uint8Array | string,
  sk: Uint8Array,
  randomizedSigning: boolean,
  ctx: Uint8Array
): number;

/**
 * Sign a message, returning signature concatenated with message
 * @param msg - Message to sign
 * @param sk - Secret key
 * @param randomizedSigning - If true, use random nonce; if false, deterministic
 * @param ctx - Context string (max 255 bytes)
 * @returns Signed message (signature || message)
 * @throws Error if signing fails
 */
export function cryptoSign(
  msg: Uint8Array | string,
  sk: Uint8Array,
  randomizedSigning: boolean,
  ctx: Uint8Array
): Uint8Array;

/**
 * Verify a signature
 * @param sig - Signature to verify
 * @param m - Message that was signed (hex string or Uint8Array; strings are parsed as hex only)
 * @param pk - Public key
 * @param ctx - Context string (max 255 bytes)
 * @returns true if signature is valid, false otherwise
 */
export function cryptoSignVerify(
  sig: Uint8Array,
  m: Uint8Array | string,
  pk: Uint8Array,
  ctx: Uint8Array
): boolean;

/**
 * Open a signed message (verify and extract message)
 * @param sm - Signed message (signature || message)
 * @param pk - Public key
 * @param ctx - Context string (max 255 bytes)
 * @returns Message if valid, undefined if verification fails
 */
export function cryptoSignOpen(
  sm: Uint8Array,
  pk: Uint8Array,
  ctx: Uint8Array
): Uint8Array | undefined;

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

// Internal classes (exported but primarily for internal use)

export class Poly {
  coeffs: Int32Array;
  constructor();
  copy(poly: Poly): void;
}

export class PolyVecK {
  vec: Poly[];
  constructor();
}

export class PolyVecL {
  vec: Poly[];
  constructor();
  copy(polyVecL: PolyVecL): void;
}

export class KeccakState {
  constructor();
}

// Internal functions (exported but primarily for internal use)
export function polyNTT(a: Poly): void;
export function polyInvNTTToMont(a: Poly): void;
export function polyChallenge(c: Poly, seed: Uint8Array): void;
export function ntt(a: Int32Array): void;
export function invNTTToMont(a: Int32Array): void;
export function montgomeryReduce(a: bigint): bigint;
export function reduce32(a: number): number;
export function cAddQ(a: number): number;
export function decompose(a0: Int32Array, i: number, a: number): number;
export function power2round(a0: Int32Array, i: number, a: number): number;
export function makeHint(a0: number, a1: number): number;
export function useHint(a: number, hint: number): number;
export function packPk(pk: Uint8Array, rho: Uint8Array, t1: PolyVecK): void;
export function packSk(
  sk: Uint8Array,
  rho: Uint8Array,
  tr: Uint8Array,
  key: Uint8Array,
  t0: PolyVecK,
  s1: PolyVecL,
  s2: PolyVecK
): void;
export function packSig(
  sig: Uint8Array,
  c: Uint8Array,
  z: PolyVecL,
  h: PolyVecK
): void;
export function unpackPk(rho: Uint8Array, t1: PolyVecK, pk: Uint8Array): void;
export function unpackSk(
  rho: Uint8Array,
  tr: Uint8Array,
  key: Uint8Array,
  t0: PolyVecK,
  s1: PolyVecL,
  s2: PolyVecK,
  sk: Uint8Array
): void;
export function unpackSig(
  c: Uint8Array,
  z: PolyVecL,
  h: PolyVecK,
  sig: Uint8Array
): number;

// FIPS 202 SHAKE primitives (low-level XOF interface, primarily internal)
export function shake128Init(state: KeccakState): void;
export function shake128Absorb(state: KeccakState, input: Uint8Array): void;
export function shake128Finalize(state: KeccakState): void;
export function shake128SqueezeBlocks(
  out: Uint8Array,
  outputOffset: number,
  nBlocks: number,
  state: KeccakState
): void;
export function shake256Init(state: KeccakState): void;
export function shake256Absorb(state: KeccakState, input: Uint8Array): void;
export function shake256Finalize(state: KeccakState): void;
export function shake256SqueezeBlocks(
  out: Uint8Array,
  outputOffset: number,
  nBlocks: number,
  state: KeccakState
): void;

// ML-DSA-specific stream initializers
export function mldsaShake128StreamInit(
  state: KeccakState,
  seed: Uint8Array,
  nonce: number
): void;
export function mldsaShake256StreamInit(
  state: KeccakState,
  seed: Uint8Array,
  nonce: number
): void;

// Polynomial operations (internal)
export function polyReduce(a: Poly): void;
export function polyCAddQ(a: Poly): void;
export function polyAdd(c: Poly, a: Poly, b: Poly): void;
export function polySub(c: Poly, a: Poly, b: Poly): void;
export function polyShiftL(a: Poly): void;
export function polyPointWiseMontgomery(c: Poly, a: Poly, b: Poly): void;
export function polyPower2round(a1: Poly, a0: Poly, a: Poly): void;
export function polyDecompose(a1: Poly, a0: Poly, a: Poly): void;
export function polyMakeHint(h: Poly, a0: Poly, a1: Poly): number;
export function polyUseHint(b: Poly, a: Poly, h: Poly): void;
export function polyChkNorm(a: Poly, b: number): number;
export function rejUniform(
  a: Int32Array,
  aOffset: number,
  len: number,
  buf: Uint8Array,
  bufLen: number
): number;
export function polyUniform(a: Poly, seed: Uint8Array, nonce: number): void;
export function rejEta(
  a: Int32Array,
  aOffset: number,
  len: number,
  buf: Uint8Array,
  bufLen: number
): number;
export function polyUniformEta(a: Poly, seed: Uint8Array, nonce: number): void;
export function polyZUnpack(r: Poly, a: Uint8Array, aOffset: number): void;
export function polyUniformGamma1(a: Poly, seed: Uint8Array, nonce: number): void;
export function polyEtaPack(r: Uint8Array, rOffset: number, a: Poly): void;
export function polyEtaUnpack(r: Poly, a: Uint8Array, aOffset: number): void;
export function polyT1Pack(r: Uint8Array, rOffset: number, a: Poly): void;
export function polyT1Unpack(r: Poly, a: Uint8Array, aOffset: number): void;
export function polyT0Pack(r: Uint8Array, rOffset: number, a: Poly): void;
export function polyT0Unpack(r: Poly, a: Uint8Array, aOffset: number): void;
export function polyZPack(r: Uint8Array, rOffset: number, a: Poly): void;
export function polyW1Pack(r: Uint8Array, rOffset: number, a: Poly): void;

// Polynomial vector operations (internal)
export function polyVecMatrixExpand(mat: PolyVecL[], rho: Uint8Array): void;
export function polyVecMatrixPointWiseMontgomery(
  t: PolyVecK,
  mat: PolyVecL[],
  v: PolyVecL
): void;
export function polyVecLUniformEta(v: PolyVecL, seed: Uint8Array, nonce: number): void;
export function polyVecLUniformGamma1(v: PolyVecL, seed: Uint8Array, nonce: number): void;
export function polyVecLReduce(v: PolyVecL): void;
export function polyVecLAdd(w: PolyVecL, u: PolyVecL, v: PolyVecL): void;
export function polyVecLNTT(v: PolyVecL): void;
export function polyVecLInvNTTToMont(v: PolyVecL): void;
export function polyVecLPointWisePolyMontgomery(
  r: PolyVecL,
  a: Poly,
  v: PolyVecL
): void;
export function polyVecLPointWiseAccMontgomery(
  w: Poly,
  u: PolyVecL,
  v: PolyVecL
): void;
export function polyVecLChkNorm(v: PolyVecL, bound: number): number;
export function polyVecKUniformEta(v: PolyVecK, seed: Uint8Array, nonce: number): void;
export function polyVecKReduce(v: PolyVecK): void;
export function polyVecKCAddQ(v: PolyVecK): void;
export function polyVecKAdd(w: PolyVecK, u: PolyVecK, v: PolyVecK): void;
export function polyVecKSub(w: PolyVecK, u: PolyVecK, v: PolyVecK): void;
export function polyVecKShiftL(v: PolyVecK): void;
export function polyVecKNTT(v: PolyVecK): void;
export function polyVecKInvNTTToMont(v: PolyVecK): void;
export function polyVecKPointWisePolyMontgomery(
  r: PolyVecK,
  a: Poly,
  v: PolyVecK
): void;
export function polyVecKChkNorm(v: PolyVecK, bound: number): number;
export function polyVecKPower2round(v1: PolyVecK, v0: PolyVecK, v: PolyVecK): void;
export function polyVecKDecompose(v1: PolyVecK, v0: PolyVecK, v: PolyVecK): void;
export function polyVecKMakeHint(h: PolyVecK, v0: PolyVecK, v1: PolyVecK): number;
export function polyVecKUseHint(w: PolyVecK, u: PolyVecK, h: PolyVecK): void;
export function polyVecKPackW1(r: Uint8Array, w1: PolyVecK): void;
