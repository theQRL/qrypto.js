/// <reference path="typedefs.js" />

import { newBDSState, newXMSSParams } from './classes.js';
import { COMMON, WOTS_PARAM } from './constants.js';
import { XMSSFastGenKeyPair } from './xmssFast.js';

/**
 * @param {QRLDescriptor} desc
 * @param {Uint8Array} seed
 * @returns {XMSS}
 */
export function initializeTree(desc, seed) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }
  const [height] = new Uint32Array([desc.getHeight()]);
  const hashFunction = desc.getHashFunction();
  const sk = new Uint8Array(132);
  const pk = new Uint8Array(64);

  const k = WOTS_PARAM.K;
  const w = WOTS_PARAM.W;
  const n = WOTS_PARAM.N;

  if (k >= height || (height - k) % 2 === 1) {
    throw new Error('For BDS traversal, H - K must be even, with H > K >= 2!');
  }

  const xmssParams = newXMSSParams(n, height, w, k);
  const bdsState = newBDSState(height, n, k);
  XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed);

  return {
    xmssParams,
    hashFunction,
    height,
    sk,
    seed,
    bdsState,
    desc,
  };
}

export const temp = 1;
