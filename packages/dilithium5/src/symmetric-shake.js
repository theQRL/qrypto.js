const {
  shake128Absorb,
  shake128Finalize,
  shake128Init,
  shake256Absorb,
  shake256Finalize,
  shake256Init,
} = require('./fips202.js');
const { CRHBytes, SeedBytes } = require('./const.js');

function dilithiumShake128StreamInit(state, seed, nonce) {
  if (seed.length !== SeedBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${SeedBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake128Init(state);
  shake128Absorb(state, seed);
  shake128Absorb(state, t);
  shake128Finalize(state);
}

function dilithiumShake256StreamInit(state, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${CRHBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Absorb(state, t);
  shake256Finalize(state);
}

module.exports = {
  dilithiumShake128StreamInit,
  dilithiumShake256StreamInit,
};
