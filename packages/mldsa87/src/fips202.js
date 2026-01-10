/**
 * FIPS 202 SHAKE functions using @noble/hashes
 * Provides streaming XOF (extendable output function) interface
 */

import { shake128 as nobleShake128, shake256 as nobleShake256 } from '@noble/hashes/sha3';
import { Shake128Rate, Shake256Rate } from './const.js';

/**
 * Keccak state wrapper for @noble/hashes
 * Maintains hasher instance for streaming operations
 */
export class KeccakState {
  constructor() {
    this.hasher = null;
    this.finalized = false;
  }
}

// SHAKE-128 functions

export function shake128Init(state) {
  state.hasher = nobleShake128.create({});
  state.finalized = false;
}

export function shake128Absorb(state, input) {
  state.hasher.update(input);
}

export function shake128Finalize(state) {
  // Mark as finalized - actual finalization happens on first xofInto call
  state.finalized = true;
}

export function shake128SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake128Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}

// SHAKE-256 functions

export function shake256Init(state) {
  state.hasher = nobleShake256.create({});
  state.finalized = false;
}

export function shake256Absorb(state, input) {
  state.hasher.update(input);
}

export function shake256Finalize(state) {
  // Mark as finalized - actual finalization happens on first xofInto call
  state.finalized = true;
}

export function shake256SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake256Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}
