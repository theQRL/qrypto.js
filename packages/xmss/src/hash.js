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
 * @returns {Uint8Array}
 */
export function coreHash(hashFunction, out, typeValue, key, keyLen, input, inLen, n) {
  let outValue = out;
  let buf = new Uint8Array(inLen + n + keyLen);
  buf = toByteLittleEndian(buf, typeValue, n);
  for (let i = new Uint32Array([0])[0]; i < keyLen; i++) {
    buf.set([key[i]], i + n);
  }
  for (let i = new Uint32Array([0])[0]; i < inLen; i++) {
    buf.set([input[i]], keyLen + n + i);
  }

  switch (hashFunction) {
    case HASH_FUNCTION.SHA2_256:
      outValue = sha256(outValue, buf);
      break;
    case HASH_FUNCTION.SHAKE_128:
      outValue = shake128(outValue, buf);
      break;
    case HASH_FUNCTION.SHAKE_256:
      outValue = shake256(outValue, buf);
      break;
    default:
      break;
  }
  return outValue;
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @returns {Uint8Array}
 */
export function prf(hashFunction, out, input, key, keyLen) {
  return coreHash(hashFunction, out, 3, key, keyLen, input, 32, keyLen);
}

// TODO: Once all objects are modified as reference, complete this.
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 * @returns {Uint8Array}
 */
export function hashH(hashFunction, out, input, pubSeed, addr, n) {
  let addrValue = addr;
  const buf = new Uint8Array(2 * n);
  let key = new Uint8Array(n);
  const bitMask = new Uint8Array(2 * n);
  let byteAddr = new Uint8Array(32);

  addrValue = setKeyAndMask(addrValue, 0);
  byteAddr = addrToByte(byteAddr, addrValue);
  key = prf(hashFunction, key, byteAddr, pubSeed, n);

  // Use MSB order
  addrValue = setKeyAndMask(addrValue, 1);
  byteAddr = addrToByte(byteAddr, addrValue);
  bitMask = prf(hashFunction, bitMask.subarray(0, n), byteAddr, pubSeed, n);

  // prf(hashFunction, bitMask[:n], byteAddr[:], pubSeed, n)
  // misc.SetKeyAndMask(addr, 2)
  // misc.AddrToByte(&byteAddr, addr)
  // prf(hashFunction, bitMask[n:n+n], byteAddr[:], pubSeed, n)
  // for i := uint32(0); i < 2*n; i++ {
  // 	buf[i] = input[i] ^ bitMask[i]
  // }
  // coreHash(hashFunction, out, 1, key, n, buf, 2*n, n)
}
