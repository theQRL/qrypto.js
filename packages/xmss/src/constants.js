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
  SHA256_2X: 0,
});

export const WOTS_PARAM = Object.freeze({
  K: 2,
  W: 16,
  N: 32,
});

export const OFFSET_IDX = 0;
export const OFFSET_SK_SEED = OFFSET_IDX + 4;
export const OFFSET_SK_PRF = OFFSET_SK_SEED + 32;
export const OFFSET_PUB_SEED = OFFSET_SK_PRF + 32;
export const OFFSET_ROOT = OFFSET_PUB_SEED + 32;
