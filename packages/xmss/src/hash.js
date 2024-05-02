/// <reference path="typedefs.js" />

import { HASH_FUNCTION } from './constants.js';
import { addrToByte, setKeyAndMask, sha256, shake128, shake256, toByteLittleEndian } from './helper.js';

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} typeValue
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} inLen
 * @param {Uint32Array[number]} n
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 */
export function coreHash(
  hashFunction,
  out,
  typeValue,
  key,
  keyLen,
  input,
  inLen,
  n,
  outStartIndex = 0,
  outEndIndex = out.length
) {
  const buf = new Uint8Array(inLen + n + keyLen);
  toByteLittleEndian(buf, typeValue, n);
  for (let i = new Uint32Array([0])[0]; i < keyLen; i++) {
    buf.set([key[i]], i + n);
  }
  for (let i = new Uint32Array([0])[0]; i < inLen; i++) {
    buf.set([input[i]], keyLen + n + i);
  }

  switch (hashFunction) {
    case HASH_FUNCTION.SHA2_256:
      sha256(out, buf, outStartIndex, outEndIndex);
      break;
    case HASH_FUNCTION.SHAKE_128:
      shake128(out, buf, outStartIndex, outEndIndex);
      break;
    case HASH_FUNCTION.SHAKE_256:
      shake256(out, buf, outStartIndex, outEndIndex);
      break;
    default:
      break;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 */
export function prf(hashFunction, out, input, key, keyLen, outStartIndex = 0, outEndIndex = out.length) {
  coreHash(hashFunction, out, 3, key, keyLen, input, 32, keyLen, outStartIndex, outEndIndex);
}

// TODO: Once all objects are modified as reference, complete this.
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 * @returns {HashHReturnType}
 */
export function hashH(hashFunction, out, input, pubSeed, addr, n) {
  const buf = new Uint8Array(2 * n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(2 * n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  // Use MSB order
  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n, 0, n);
  setKeyAndMask(addr, 2);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n, n, n + n);
  for (let i = new Uint32Array([0])[0]; i < 2 * n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 1, key, n, buf, 2 * n, n);

  return {
    hashFunction,
    out,
    input,
    pubSeed,
    addr,
    n,
  };
}
