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

/**
 * @param {Uint8Array | Uint32Array} uIntArray
 * @param {keyof typeof UINT} variant
 * @returns {string}
 */
export const getHexFromUIntArray = (uIntArray, variant) => {
  let charSize;
  switch (variant) {
    case UINT[32]:
      charSize = 8;
      break;
    default:
      charSize = 2;
      break;
  }
  const hexString = Array.from(uIntArray)
    .map((byte) => byte.toString(16).padStart(charSize, '0'))
    .join('');
  console.log('>>>hexString: ', hexString);

  return hexString;
};

/**
 * @param {Uint8Array | Uint32Array} uIntArray
 * @param {keyof typeof UINT} variant
 * @returns {Uint8Array | Uint32Array}
 */
export const getRecreatedUIntArray = (uIntArray, variant) => {
  const hexString = getHexFromUIntArray(uIntArray, variant);
  const recreatedUIntArray = getUIntArrayFromHex(hexString, variant);
  return recreatedUIntArray;
};

getHexFromUIntArray(
  new Uint8Array([
    102, 25, 153, 94, 80, 214, 241, 97, 162, 182, 144, 99, 214, 38, 231, 227, 119, 188, 178, 202, 22, 56, 171, 125, 111,
    0, 211, 152, 129, 100, 89, 132, 105, 56, 52, 86, 112, 147, 92, 125, 232, 52, 36, 136, 247, 132, 140, 97, 32, 216,
    217, 65, 247, 236, 104, 107, 3, 57, 23, 172, 136, 102, 73, 78, 88, 47, 212,
  ]),
  UINT[8]
);
