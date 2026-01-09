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
 * @param m - Message to sign (hex-encoded string)
 * @param sk - Secret key
 * @param randomizedSigning - If true, use random nonce; if false, deterministic
 * @returns 0 on success
 * @throws Error if sk is wrong size
 */
export function cryptoSignSignature(
  sig: Uint8Array,
  m: string,
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
  msg: Uint8Array,
  sk: Uint8Array,
  randomizedSigning: boolean
): Uint8Array;

/**
 * Verify a signature
 * @param sig - Signature to verify
 * @param m - Message that was signed (hex-encoded string)
 * @param pk - Public key
 * @returns true if signature is valid, false otherwise
 */
export function cryptoSignVerify(
  sig: Uint8Array,
  m: string,
  pk: Uint8Array
): boolean;

/**
 * Open a signed message (verify and extract message)
 * @param sm - Signed message (signature || message)
 * @param pk - Public key
 * @returns Message if valid, undefined if verification fails
 */
export function cryptoSignOpen(
  sm: Uint8Array,
  pk: Uint8Array
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
