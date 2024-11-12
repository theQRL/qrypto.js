/* The following functions are only used within this library for testing purposes, and not part of the library for end user. */

export const UINT = {
  8: 8,
  32: 32,
};

/**
 * @param {string} hexString
 * @param {keyof typeof UINT} variant
 * @returns {Uint8Array | Uint32Array}
 */
export const getUIntArrayFromHex = (hexString, variant) => {
  let charSize;
  let strLength;
  let uIntArray;
  switch (variant) {
    case UINT[32]:
      charSize = 8;
      strLength = hexString.length / charSize;
      uIntArray = new Uint32Array(strLength);
      break;
    default:
      charSize = 2;
      strLength = hexString.length / charSize;
      uIntArray = new Uint8Array(strLength);
      break;
  }

  for (let i = 0; i < strLength; i++) {
    const element = parseInt(hexString.substring(i * charSize, i * charSize + charSize), 16);
    uIntArray.set([element], i);
  }

  return uIntArray;
};

export const getUInt8ArrayFromHex = (hexString) => getUIntArrayFromHex(hexString, UINT[8]);

export const getUInt32ArrayFromHex = (hexString) => getUIntArrayFromHex(hexString, UINT[32]);
