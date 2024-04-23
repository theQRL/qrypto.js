import jsSha3CommonJsPackage from 'js-sha3';
const { shake256: sha3Shake256 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} message
 * @returns {Uint8Array}
 */
export function shake256(out, message) {
  const outUInt8Length = out.length * 8;
  const hash = sha3Shake256(message, outUInt8Length);

  for (let i = 0; i < outUInt8Length; i += 2) {
    out[i / 2] = parseInt(hash.substring(i, i + 2), 16);
  }
  return out;
}
