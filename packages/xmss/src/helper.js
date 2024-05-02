import { sha256 as sha2Func256 } from '@noble/hashes/sha256';
import jsSha3CommonJsPackage from 'js-sha3';
import { ENDIAN } from './constants.js';

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 * @returns {Uint8Array}
 */
export function shake128(out, msg, outStartIndex = 0, outEndIndex = out.length) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let o = outStartIndex, h = 0; o < outEndIndex; o++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], o);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 * @returns {Uint8Array}
 */
export function shake256(out, msg, outStartIndex = 0, outEndIndex = out.length) {
  const hash = sha3Shake256(msg, 8 * out.length);
  for (let o = outStartIndex, h = 0; o < outEndIndex; o++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], o);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 * @returns {Uint8Array}
 */
export function sha256(out, msg, outStartIndex = 0, outEndIndex = out.length) {
  const hashOut = sha2Func256(msg);
  for (let o = outStartIndex, h = 0; o < outEndIndex; o++, h++) {
    out.set([hashOut[h]], o);
  }
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} typeValue
 */
export function setType(addr, typeValue) {
  addr.set([typeValue], 3);
  for (let i = 4; i < 8; i++) {
    addr.set([0], i);
  }
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 */
export function setChainAddr(addr, chain) {
  addr.set([chain], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 */
export function setHashAddr(addr, hash) {
  addr.set([hash], 6);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 */
export function setKeyAndMask(addr, keyAndMask) {
  addr.set([keyAndMask], 7);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeHeight
 */
export function setTreeHeight(addr, treeHeight) {
  addr.set([treeHeight], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeIndex
 */
export function setTreeIndex(addr, treeIndex) {
  addr.set([treeIndex], 6);
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
 * @param {number} outStartIndex
 */
export function toByteLittleEndian(out, input, bytes, outStartIndex = 0, outEndIndex = outStartIndex + bytes - 1) {
  let inValue = input;
  for (let o = outEndIndex; o >= outStartIndex; o--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], o);
    inValue >>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 * @param {number} outStartIndex
 */
function toByteBigEndian(out, input, bytes, outStartIndex, outEndIndex = outStartIndex + bytes) {
  let inValue = input;
  for (let o = outStartIndex; o < outEndIndex; o++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], o);
    inValue >>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
export function addrToByte(out, addr, getEndianFunc = getEndian) {
  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        toByteLittleEndian(out, addr[i], 4, i * 4);
      }
      break;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        toByteBigEndian(out, addr[i], 4, i * 4);
      }
      break;
    default:
      throw new Error('Invalid Endian');
  }
}
