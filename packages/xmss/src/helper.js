import { sha256 as sha2Func256 } from '@noble/hashes/sha256';
import jsSha3CommonJsPackage from 'js-sha3';
import { ENDIAN } from './constants.js';

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function shake128(out, msg) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let i = 0; i < out.length; i += 1) {
    out.set([parseInt(hash.substring(i * 2, i * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function shake256(out, msg) {
  const hash = sha3Shake256(msg, 8 * out.length);
  for (let i = 0; i < out.length; i += 1) {
    out.set([parseInt(hash.substring(i * 2, i * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function sha256(out, msg) {
  const hashOut = sha2Func256(msg);
  for (let i = 0; i < out.length; i++) {
    out.set([hashOut[i]], i);
  }
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 * @returns {Uint32Array}
 */
export function setChainAddr(addr, chain) {
  addr.set([chain], 5);
  return addr;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 * @returns {Uint32Array}
 */
export function setHashAddr(addr, hash) {
  addr.set([hash], 6);
  return addr;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 * @returns {Uint32Array}
 */
export function setKeyAndMask(addr, keyAndMask) {
  addr.set([keyAndMask], 7);
  return addr;
}

/** @returns Number */
function getEndian() {
  const buffer = new ArrayBuffer(2);
  const uint16View = new Uint16Array(buffer);
  const uint8View = new Uint8Array(buffer);
  uint16View[0] = 0xabcd;
  if (uint8View[0] === 0xcd && uint8View[1] === 0xab) {
    return ENDIAN.LITTLE;
  }
  if (uint8View[0] === 0xab && uint8View[1] === 0xcd) {
    return ENDIAN.BIG;
  }
  throw new Error('Could not determine native endian.');
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 * @returns {Uint8Array}
 */
export function toByteLittleEndian(out, input, bytes) {
  let inValue = input;
  for (let i = new Int32Array([bytes - 1])[0]; i >= 0; i--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>= 8;
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 * @returns {Uint8Array}
 */
function toByteBigEndian(out, input, bytes) {
  let inValue = input;
  for (let i = new Int32Array([0])[0]; i < bytes; i++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>= 8;
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @returns {Uint8Array}
 */
export function addrToByte(out, addr, getEndianFunc = getEndian) {
  const outValue = out;
  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        const startInd = i * 4;
        outValue.set(toByteLittleEndian(outValue.slice(startInd, startInd + 4), addr[i], 4), startInd);
      }
      return outValue;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        const startInd = i * 4;
        outValue.set(toByteBigEndian(outValue.slice(startInd, startInd + 4), addr[i], 4), startInd);
      }
      return outValue;
    default:
      throw new Error('Invalid Endian');
  }
}
