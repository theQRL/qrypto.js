import { N, zetas } from './const.js';
import { montgomeryReduce } from './reduce.js';

export function ntt(a) {
  let k = 0;
  let j = 0;

  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = zetas[++k];
      for (j = start; j < start + len; ++j) {
        const t = Number(montgomeryReduce(BigInt.asIntN(64, BigInt(zeta) * BigInt(a[j + len]))));
        a[j + len] = a[j] - t; // eslint-disable-line no-param-reassign
        // eslint-disable-next-line
        a[j] = a[j] + t;
      }
    }
  }
}

export function invNTTToMont(a) {
  const f = 41978n; // mont^2/256
  let j = 0;
  let k = 256;

  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = BigInt.asIntN(32, BigInt(-zetas[--k]));
      for (j = start; j < start + len; ++j) {
        const t = a[j];
        a[j] = t + a[j + len]; // eslint-disable-line no-param-reassign
        a[j + len] = t - a[j + len]; // eslint-disable-line no-param-reassign
        a[j + len] = Number(montgomeryReduce(BigInt.asIntN(64, zeta * BigInt(a[j + len])))); // eslint-disable-line no-param-reassign
      }
    }
  }
  // eslint-disable-next-line no-shadow
  for (let j = 0; j < N; ++j) {
    a[j] = Number(montgomeryReduce(BigInt.asIntN(64, f * BigInt(a[j])))); // eslint-disable-line no-param-reassign
  }
}
