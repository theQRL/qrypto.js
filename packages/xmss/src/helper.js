import jsSha3CommonJsPackage from 'js-sha3';
const { shake256: sha3Shake256 } = jsSha3CommonJsPackage;
import { ENDIAN } from './constants.js';

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function shake256(out, msg) {
  const outUInt8Length = out.length * 8;
  const hash = sha3Shake256(msg, outUInt8Length);

  for (let i = 0; i < outUInt8Length; i += 2) {
    out[i / 2] = parseInt(hash.substring(i, i + 2), 16);
  }
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 * @returns {Uint32Array}
 */
export function setChainAddr(addr, chain) {
  addr[5] = chain;
  return addr;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 * @returns {Uint32Array}
 */
export function setHashAddr(addr, hash) {
  addr[6] = hash;
  return addr;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 * @returns {Uint32Array}
 */
export function setKeyAndMask(addr, keyAndMask) {
  addr[7] = keyAndMask;
  return addr;
}

/** @returns Number */
export function getEndian() {
  const buffer = new ArrayBuffer(2);
  const uint16View = new Uint16Array(buffer);
  const uint8View = new Uint8Array(buffer);
  uint16View[0] = 0xabcd;

  if (uint8View[0] === 0xcd && uint8View[1] === 0xab) {
    return ENDIAN.LITTLE;
  } else if (uint8View[0] === 0xab && uint8View[1] === 0xcd) {
    return ENDIAN.BIG;
  } else {
    throw new Error('Could not determine native endian.');
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 * @returns {Uint8Array}
 */
function toByteLittleEndian(out, input, bytes) {
  for (let i = new Int32Array([bytes - 1])[0]; i >= 0; i--) {
    out[i] = new Uint8Array([input & 0xff])[0];
    input >>= 8;
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
  for (let i = new Int32Array([0])[0]; i < bytes; i++) {
    out[i] = new Uint8Array([input & 0xff])[0];
    input >>= 8;
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @returns {Uint8Array}
 */
export function addrToByte(out, addr) {
  switch (getEndian()) {
    case ENDIAN.LITTLE:
      let outLittleEndian = out;
      for (let i = 0; i < 8; i++) {
        const startInd = i * 4;
        outLittleEndian.set(toByteLittleEndian(outLittleEndian.slice(startInd, startInd + 4), addr[i], 4), startInd);
      }
      return outLittleEndian;
    case ENDIAN.BIG:
      let outBigEndian = out;
      for (let i = 0; i < 8; i++) {
        const startInd = i * 4;
        outBigEndian.set(toByteBigEndian(outBigEndian.slice(startInd, startInd + 4), addr[i], 4), startInd);
      }
      return outBigEndian;
    default:
      throw new Error('Invalid Endian');
  }
}
