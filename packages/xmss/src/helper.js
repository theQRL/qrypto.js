import { sha256 as sha2Func256 } from '@noble/hashes/sha256';
import jsSha3CommonJsPackage from 'js-sha3';
import { COMMON, ENDIAN } from './constants.js';
import WORD_LIST from './wordList.js';

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function shake128(out, msg) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
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
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
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
  for (let i = 0, h = 0; i < out.length && h < hashOut.length; i++, h++) {
    out.set([hashOut[h]], i);
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
 * @param {Uint32Array[number]} lTree
 */
export function setLTreeAddr(addr, lTree) {
  addr.set([lTree], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} ots
 */
export function setOTSAddr(addr, ots) {
  addr.set([ots], 4);
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
 */
export function toByteLittleEndian(out, input, bytes) {
  let inValue = input;
  for (let i = bytes - 1; i >= 0; i--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteBigEndian(out, input, bytes) {
  let inValue = input;
  for (let i = 0; i < bytes; i++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
export function addrToByte(out, addr, getEndianFunc = getEndian) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        toByteLittleEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        toByteBigEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    default:
      throw new Error('Invalid Endian');
  }
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
export function binToMnemonic(input) {
  if (input.length % 3 !== 0) {
    throw new Error('byte count needs to be a multiple of 3');
  }

  const buf = [];
  const separator = ' ';
  for (let nibble = 0; nibble < input.length * 2; nibble += 3) {
    const p = nibble >> 1;
    const [b1] = new Uint32Array([input[p]]);
    let [b2] = new Uint32Array([0]);
    if (p + 1 < input.length) {
      [b2] = new Uint32Array([input[p + 1]]);
    }
    let [idx] = new Uint32Array([0]);
    if (nibble % 2 === 0) {
      idx = (b1 << 4) + (b2 >> 4);
    } else {
      idx = ((b1 & 0x0f) << 8) + b2;
    }
    try {
      buf.push(WORD_LIST[idx]);
    } catch (error) {
      throw new Error(`ExtendedSeedBinToMnemonic error ${error?.message}`);
    }
  }

  return buf.join(separator);
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
export function seedBinToMnemonic(input) {
  if (input.length !== COMMON.SEED_SIZE) {
    throw new Error(`input should be an array of size ${COMMON.SEED_SIZE}`);
  }

  return binToMnemonic(input);
}

/**
 * @param {Uint8Arrayany} input
 * @returns {string}
 */
export function extendedSeedBinToMnemonic(input) {
  if (input.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`input should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  return binToMnemonic(input);
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
export function mnemonicToBin(mnemonic) {
  const mnemonicWords = mnemonic.split(' ');
  const wordCount = mnemonicWords.length;
  if (wordCount % 2 !== 0) {
    throw new Error(`Word count = ${wordCount} must be even`);
  }

  const wordLookup = {};

  for (let i = 0; i < WORD_LIST.length; i++) {
    wordLookup[WORD_LIST[i]] = i;
  }

  const result = new Uint8Array((wordCount * 15) / 10);
  let current = 0;
  let buffering = 0;
  let resultIndex = 0;
  for (let i = 0; i < wordCount; i++) {
    const w = mnemonicWords[i];
    const found = w in wordLookup;
    if (!found) {
      throw new Error('Invalid word in mnemonic');
    }
    const value = wordLookup[w];

    buffering += 3;
    current = (current << 12) + value;
    while (buffering > 2) {
      const shift = 4 * (buffering - 2);
      const mask = (1 << shift) - 1;
      const tmp = current >> shift;
      buffering -= 2;
      current &= mask;
      result.set([tmp], resultIndex);
      resultIndex++;
    }
  }

  if (buffering > 0) {
    result.set([current & 0xff], resultIndex);
    resultIndex++;
  }

  return result;
}
