/**
 * FIPS 202 SHAKE functions using @noble/hashes
 * Provides streaming XOF (extendable output function) interface
 */

import { shake128 as nobleShake128, shake256 as nobleShake256 } from '@noble/hashes/sha3.js';
import { Shake128Rate, Shake256Rate } from './const.js';

/**
 * Keccak state wrapper for @noble/hashes
 * Maintains hasher instance for streaming operations
 */
export class KeccakState {
  constructor() {
    this.hasher = null;
  }
}

// SHAKE-128 functions

export function shake128Init(state) {
  state.hasher = nobleShake128.create({});
}

export function shake128Absorb(state, input) {
  state.hasher.update(input);
}

/**
 * No-op retained for API parity with the C reference's absorb/finalize/squeeze
 * flow: @noble/hashes finalizes the sponge automatically on the first
 * xofInto() call, so there is no separate finalize step to perform.
 */
export function shake128Finalize() {}

export function shake128SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake128Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}

// SHAKE-256 functions

export function shake256Init(state) {
  state.hasher = nobleShake256.create({});
}

export function shake256Absorb(state, input) {
  state.hasher.update(input);
}

/**
 * No-op retained for API parity with the C reference's absorb/finalize/squeeze
 * flow: @noble/hashes finalizes the sponge automatically on the first
 * xofInto() call, so there is no separate finalize step to perform.
 */
export function shake256Finalize() {}

export function shake256SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake256Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}
