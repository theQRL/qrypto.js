import { shake256 } from 'js-sha3';

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function SHAKE256(out, msg) {
  let hasherString = shake256(msg, out[0]);
  const encoder = new TextEncoder();
  const utf8Bytes = encoder.encode(hasherString);
  const outUint8Array = new Uint8Array(utf8Bytes);
  return outUint8Array;
}
