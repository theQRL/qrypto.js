/* The following functions are only used within this library for testing purposes, and not part of the library for end user. */

export const U_INT_ARRAY_VARIANT = {
  8: 8,
  32: 32,
};

/**
 * @param {string} hexString
 * @param {keyof typeof U_INT_ARRAY_VARIANT} variant
 * @returns {Uint8Array | Uint32Array}
 */
export const getUIntArrayFromHex = (hexString, variant) => {
  let charSize;
  let strLength;
  let uIntArray;
  switch (variant) {
    case U_INT_ARRAY_VARIANT[32]:
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

/**
 * @param {Uint8Array | Uint32Array} uIntArray
 * @param {keyof typeof U_INT_ARRAY_VARIANT} variant
 * @returns {string}
 */
export const getHexFromUIntArray = (uIntArray, variant) => {
  let charSize;
  switch (variant) {
    case U_INT_ARRAY_VARIANT[32]:
      charSize = 8;
      break;
    default:
      charSize = 2;
      break;
  }
  const hexString = Array.from(uIntArray)
    .map((byte) => byte.toString(16).padStart(charSize, '0'))
    .join('');

  return hexString;
};

/**
 * @param {Uint8Array | Uint32Array} uIntArray
 * @param {keyof typeof U_INT_ARRAY_VARIANT} variant
 * @returns {Uint8Array | Uint32Array}
 */
export const getRecreatedUIntArray = (uIntArray, variant) => {
  const hexString = getHexFromUIntArray(uIntArray, variant);
  const recreatedUIntArray = getUIntArrayFromHex(hexString, variant);
  return recreatedUIntArray;
};
