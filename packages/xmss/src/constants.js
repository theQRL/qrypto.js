export const CONSTANTS = Object.freeze({
  EXTENDED_PK_SIZE: 67,
  MAX_HEIGHT: 254,
});

export const ENDIAN = Object.freeze({
  LITTLE: 0,
  BIG: 1,
});

export const HASH_FUNCTION = Object.freeze({
  SHA2_256: 0,
  SHAKE_128: 1,
  SHAKE_256: 2,
});

export const COMMON = Object.freeze({
  DESCRIPTOR_SIZE: 3,
  ADDRESS_SIZE: 20,
  SEED_SIZE: 48,
  EXTENDED_SEED_SIZE: 51,
  XMSS_SIG: 1,
  SHA256_2X: 0,
});

export const WOTS_PARAM = Object.freeze({
  K: 2,
  W: 16,
  N: 32,
});
