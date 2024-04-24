import jsSha3CommonJsPackage from 'js-sha3';
const { shake256: sha3Shake256 } = jsSha3CommonJsPackage;

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
