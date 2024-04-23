/// <reference path="typedefs.js" />
import { shake256 } from './helper';

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} seed
 */
export function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
  if (xmssParams.h % 2 === 1) {
    throw new Error('Not a valid h, only even numbers supported! Try again with an even number');
  }

  const n = xmssParams.n;

  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;

  // Copy PUB_SEED to public key
  let randombits = new Uint8Array(3 * n);

  //shake256(randombits, 3 * n, seed, 48);  // FIXME: seed size has been hardcoded to 48
  randombits = shake256(randombits, seed);

  const rnd = 96;
  const pks = new Uint32Array([32])[0];
  sk.set(randombits.subarray(0, rnd), 4);
  pk.set(sk.subarray(4 + 2 * n, 4 + 2 * n + pks), n);

  const addr = new Uint32Array(8);
  // TODO:
  // treeHashSetup(hashFunction, pk, 0, bdsState, sk[4:4+n], xmssParams, sk[4+2*n:4+2*n+n], addr)

  sk.set(pk.subarray(0, pks), 4 + 3 * n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} leaf
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} lTreeAddr
 * @param {Uint32Array} otsAddr
 */
export function genLeafWOTS(hashFunction, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr) {
  const seed = new Uint8Array(xmssParams.n);
  const pk = new Uint8Array(xmssParams.wotsParams.keySize);

  // TODO:
  // getSeed(hashFunction, seed, skSeed, xmssParams.n, otsAddr)
  // wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr)
  // lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr)
}
