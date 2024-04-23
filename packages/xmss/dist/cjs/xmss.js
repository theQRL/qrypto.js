'use strict';

var jsSha3CommonJsPackage = require('js-sha3');

const { shake256: sha3Shake256 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} message
 * @returns {Uint8Array}
 */
function shake256(out, message) {
  const outUInt8Length = out.length * 8;
  const hash = sha3Shake256(message, outUInt8Length);

  for (let i = 0; i < outUInt8Length; i += 2) {
    out[i / 2] = parseInt(hash.substring(i, i + 2), 16);
  }
  return out;
}

/**
 * @param {Uint32Array[number]} hashFunction
 * @param {{
 *   wotsParams: {
 *     len1: Uint32Array[number];
 *     len2: Uint32Array[number];
 *     len: Uint32Array[number];
 *     n: Uint32Array[number];
 *     w: Uint32Array[number];
 *     logW: Uint32Array[number];
 *     keySize: Uint32Array[number];
 *   };
 *   n: Uint32Array[number];
 *   h: Uint32Array[number];
 *   k: Uint32Array[number];
 * }} xmssParams
 *
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {{
 *   stack: Uint8Array;
 *   stackOffset: Uint32Array[number];
 *   stackLevels: Uint8Array;
 *   auth: Uint8Array;
 *   keep: Uint8Array;
 *   treeHash: {
 *     h: Uint32Array[number];
 *     nextIdx: Uint32Array[number];
 *     stackUsage: Uint32Array[number];
 *     completed: Uint8Array[number];
 *     node: Uint8Array;
 *   };
 *   retain: Uint8Array;
 *   nextLeaf: Uint32Array[number];
 * }} bdsState
 * @param {Uint8Array} seed
 */
function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
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
  // treeHashSetup(hashFunction, pk, 0, bdsState, sk[4:4+n], xmssParams, sk[4+2*n:4+2*n+n], addr)

  sk.set(pk.subarray(0, pks), 4 + 3 * n);
}

exports.XMSSFastGenKeyPair = XMSSFastGenKeyPair;
exports.shake256 = shake256;
