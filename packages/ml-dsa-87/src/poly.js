import {
  D,
  ETA,
  GAMMA1,
  N,
  PolyUniformETANBlocks,
  PolyUniformGamma1NBlocks,
  PolyUniformNBlocks,
  Q,
  SeedBytes,
  Shake256Rate,
  Stream128BlockBytes,
  Stream256BlockBytes,
  TAU,
  CTILDEBytes,
} from './const.js';

import {
  KeccakState,
  shake128SqueezeBlocks,
  shake256Absorb,
  shake256Finalize,
  shake256Init,
  shake256SqueezeBlocks,
} from './fips202.js';

import { dilithiumShake128StreamInit, dilithiumShake256StreamInit } from './symmetric-shake.js';
import { invNTTToMont, ntt } from './ntt.js';
import { cAddQ, montgomeryReduce, reduce32 } from './reduce.js';
import { decompose, makeHint, power2round, useHint } from './rounding.js';

export class Poly {
  constructor() {
    this.coeffs = new Int32Array(N);
  }

  copy(poly) {
    for (let i = N - 1; i >= 0; i--) {
      this.coeffs[i] = poly.coeffs[i];
    }
  }
}

export function polyReduce(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = reduce32(a.coeffs[i]);
}

export function polyCAddQ(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = cAddQ(a.coeffs[i]);
}

export function polyAdd(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
}

export function polySub(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
}

export function polyShiftL(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] <<= D;
}

export function polyNTT(a) {
  ntt(a.coeffs);
}

export function polyInvNTTToMont(a) {
  invNTTToMont(a.coeffs);
}

export function polyPointWiseMontgomery(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = Number(montgomeryReduce(BigInt(a.coeffs[i]) * BigInt(b.coeffs[i])));
}

export function polyPower2round(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = power2round(a0.coeffs, i, a.coeffs[i]);
}

export function polyDecompose(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = decompose(a0.coeffs, i, a.coeffs[i]);
}

export function polyMakeHint(hp, a0, a1) {
  let s = 0;
  const h = hp;
  for (let i = 0; i < N; ++i) {
    h.coeffs[i] = makeHint(a0.coeffs[i], a1.coeffs[i]);
    s += h.coeffs[i];
  }

  return s;
}

export function polyUseHint(bp, a, h) {
  const b = bp;
  for (let i = 0; i < N; ++i) {
    b.coeffs[i] = useHint(a.coeffs[i], h.coeffs[i]);
  }
}

export function polyChkNorm(a, b) {
  if (b > Math.floor((Q - 1) / 8)) {
    return 1;
  }

  for (let i = 0; i < N; i++) {
    let t = a.coeffs[i] >> 31;
    t = a.coeffs[i] - (t & (2 * a.coeffs[i]));

    if (t >= b) {
      return 1;
    }
  }

  return 0;
}

export function rejUniform(ap, aOffset, len, buf, bufLen) {
  let ctr = 0;
  let pos = 0;
  const a = ap;
  while (ctr < len && pos + 3 <= bufLen) {
    let t = buf[pos++];
    t |= buf[pos++] << 8;
    t |= buf[pos++] << 16;
    t &= 0x7fffff;

    if (t < Q) {
      a[aOffset + ctr++] = t;
    }
  }

  return ctr;
}

export function polyUniform(a, seed, nonce) {
  let off = 0;
  let bufLen = PolyUniformNBlocks * Stream128BlockBytes;
  const buf = new Uint8Array(PolyUniformNBlocks * Stream128BlockBytes + 2);

  const state = new KeccakState();
  dilithiumShake128StreamInit(state, seed, nonce);
  shake128SqueezeBlocks(buf, off, PolyUniformNBlocks, state);

  let ctr = rejUniform(a.coeffs, 0, N, buf, bufLen);

  while (ctr < N) {
    off = bufLen % 3;
    for (let i = 0; i < off; ++i) buf[i] = buf[bufLen - off + i];

    shake128SqueezeBlocks(buf, off, 1, state);
    bufLen = Stream128BlockBytes + off;
    ctr += rejUniform(a.coeffs, ctr, N - ctr, buf, bufLen);
  }
}

export function rejEta(aP, aOffset, len, buf, bufLen) {
  let ctr;
  let pos;
  let t0;
  let t1;
  const a = aP;
  ctr = 0;
  pos = 0;
  while (ctr < len && pos < bufLen) {
    t0 = buf[pos] & 0x0f;
    t1 = buf[pos++] >> 4;

    if (t0 < 15) {
      t0 -= ((205 * t0) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t0;
    }
    if (t1 < 15 && ctr < len) {
      t1 -= ((205 * t1) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t1;
    }
  }

  return ctr;
}

export function polyUniformEta(a, seed, nonce) {
  let ctr;
  const bufLen = PolyUniformETANBlocks * Stream256BlockBytes;
  const buf = new Uint8Array(bufLen);

  const state = new KeccakState();
  dilithiumShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformETANBlocks, state);

  ctr = rejEta(a.coeffs, 0, N, buf, bufLen);
  while (ctr < N) {
    shake256SqueezeBlocks(buf, 0, 1, state);
    ctr += rejEta(a.coeffs, ctr, N - ctr, buf, Stream256BlockBytes);
  }
}

export function polyZUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r.coeffs[2 * i] = a[aOffset + 5 * i];
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 1] << 8;
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 2] << 16;
    r.coeffs[2 * i] &= 0xfffff;

    r.coeffs[2 * i + 1] = a[aOffset + 5 * i + 2] >> 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 3] << 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 4] << 12;
    r.coeffs[2 * i] &= 0xfffff;

    r.coeffs[2 * i] = GAMMA1 - r.coeffs[2 * i];
    r.coeffs[2 * i + 1] = GAMMA1 - r.coeffs[2 * i + 1];
  }
}

export function polyUniformGamma1(a, seed, nonce) {
  const buf = new Uint8Array(PolyUniformGamma1NBlocks * Stream256BlockBytes);

  const state = new KeccakState();
  dilithiumShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformGamma1NBlocks, state);
  polyZUnpack(a, buf, 0);
}

export function polyChallenge(cP, seed) {
  if (seed.length !== CTILDEBytes) throw new Error('invalid ctilde length');

  let b;
  let pos;
  const c = cP;
  const buf = new Uint8Array(Shake256Rate);

  const state = new KeccakState();
  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Finalize(state);
  shake256SqueezeBlocks(buf, 0, 1, state);

  let signs = 0n;
  for (let i = 0; i < 8; ++i) {
    signs = BigInt.asUintN(64, signs | (BigInt(buf[i]) << BigInt(8 * i)));
  }
  pos = 8;

  for (let i = 0; i < N; ++i) {
    c.coeffs[i] = 0;
  }
  for (let i = N - TAU; i < N; ++i) {
    do {
      if (pos >= Shake256Rate) {
        shake256SqueezeBlocks(buf, 0, 1, state);
        pos = 0;
      }

      b = buf[pos++];
    } while (b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = Number(1n - 2n * (signs & 1n));
    signs >>= 1n;
  }
}

export function polyEtaPack(rP, rOffset, a) {
  const t = new Uint8Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = ETA - a.coeffs[8 * i];
    t[1] = ETA - a.coeffs[8 * i + 1];
    t[2] = ETA - a.coeffs[8 * i + 2];
    t[3] = ETA - a.coeffs[8 * i + 3];
    t[4] = ETA - a.coeffs[8 * i + 4];
    t[5] = ETA - a.coeffs[8 * i + 5];
    t[6] = ETA - a.coeffs[8 * i + 6];
    t[7] = ETA - a.coeffs[8 * i + 7];

    r[rOffset + 3 * i] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[rOffset + 3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[rOffset + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
}

export function polyEtaUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = (a[aOffset + 3 * i] >> 0) & 7;
    r.coeffs[8 * i + 1] = (a[aOffset + 3 * i] >> 3) & 7;
    r.coeffs[8 * i + 2] = ((a[aOffset + 3 * i] >> 6) | (a[aOffset + 3 * i + 1] << 2)) & 7;
    r.coeffs[8 * i + 3] = (a[aOffset + 3 * i + 1] >> 1) & 7;
    r.coeffs[8 * i + 4] = (a[aOffset + 3 * i + 1] >> 4) & 7;
    r.coeffs[8 * i + 5] = ((a[aOffset + 3 * i + 1] >> 7) | (a[aOffset + 3 * i + 2] << 1)) & 7;
    r.coeffs[8 * i + 6] = (a[aOffset + 3 * i + 2] >> 2) & 7;
    r.coeffs[8 * i + 7] = (a[aOffset + 3 * i + 2] >> 5) & 7;

    r.coeffs[8 * i] = ETA - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = ETA - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = ETA - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = ETA - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = ETA - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = ETA - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = ETA - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = ETA - r.coeffs[8 * i + 7];
  }
}

export function polyT1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r[rOffset + 5 * i] = a.coeffs[4 * i] >> 0;
    r[rOffset + 5 * i + 1] = (a.coeffs[4 * i] >> 8) | (a.coeffs[4 * i + 1] << 2);
    r[rOffset + 5 * i + 2] = (a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4);
    r[rOffset + 5 * i + 3] = (a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6);
    r[rOffset + 5 * i + 4] = a.coeffs[4 * i + 3] >> 2;
  }
}

export function polyT1Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r.coeffs[4 * i] = ((a[aOffset + 5 * i] >> 0) | (a[aOffset + 5 * i + 1] << 8)) & 0x3ff;
    r.coeffs[4 * i + 1] = ((a[aOffset + 5 * i + 1] >> 2) | (a[aOffset + 5 * i + 2] << 6)) & 0x3ff;
    r.coeffs[4 * i + 2] = ((a[aOffset + 5 * i + 2] >> 4) | (a[aOffset + 5 * i + 3] << 4)) & 0x3ff;
    r.coeffs[4 * i + 3] = ((a[aOffset + 5 * i + 3] >> 6) | (a[aOffset + 5 * i + 4] << 2)) & 0x3ff;
  }
}

export function polyT0Pack(rP, rOffset, a) {
  const t = new Uint32Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = (1 << (D - 1)) - a.coeffs[8 * i];
    t[1] = (1 << (D - 1)) - a.coeffs[8 * i + 1];
    t[2] = (1 << (D - 1)) - a.coeffs[8 * i + 2];
    t[3] = (1 << (D - 1)) - a.coeffs[8 * i + 3];
    t[4] = (1 << (D - 1)) - a.coeffs[8 * i + 4];
    t[5] = (1 << (D - 1)) - a.coeffs[8 * i + 5];
    t[6] = (1 << (D - 1)) - a.coeffs[8 * i + 6];
    t[7] = (1 << (D - 1)) - a.coeffs[8 * i + 7];

    r[rOffset + 13 * i] = t[0]; // eslint-disable-line prefer-destructuring
    r[rOffset + 13 * i + 1] = t[0] >> 8;
    r[rOffset + 13 * i + 1] |= t[1] << 5;
    r[rOffset + 13 * i + 2] = t[1] >> 3;
    r[rOffset + 13 * i + 3] = t[1] >> 11;
    r[rOffset + 13 * i + 3] |= t[2] << 2;
    r[rOffset + 13 * i + 4] = t[2] >> 6;
    r[rOffset + 13 * i + 4] |= t[3] << 7;
    r[rOffset + 13 * i + 5] = t[3] >> 1;
    r[rOffset + 13 * i + 6] = t[3] >> 9;
    r[rOffset + 13 * i + 6] |= t[4] << 4;
    r[rOffset + 13 * i + 7] = t[4] >> 4;
    r[rOffset + 13 * i + 8] = t[4] >> 12;
    r[rOffset + 13 * i + 8] |= t[5] << 1;
    r[rOffset + 13 * i + 9] = t[5] >> 7;
    r[rOffset + 13 * i + 9] |= t[6] << 6;
    r[rOffset + 13 * i + 10] = t[6] >> 2;
    r[rOffset + 13 * i + 11] = t[6] >> 10;
    r[rOffset + 13 * i + 11] |= t[7] << 3;
    r[rOffset + 13 * i + 12] = t[7] >> 5;
  }
}

export function polyT0Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = a[aOffset + 13 * i];
    r.coeffs[8 * i] |= a[aOffset + 13 * i + 1] << 8;
    r.coeffs[8 * i] &= 0x1fff;

    r.coeffs[8 * i + 1] = a[aOffset + 13 * i + 1] >> 5;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 2] << 3;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 3] << 11;
    r.coeffs[8 * i + 1] &= 0x1fff;

    r.coeffs[8 * i + 2] = a[aOffset + 13 * i + 3] >> 2;
    r.coeffs[8 * i + 2] |= a[aOffset + 13 * i + 4] << 6;
    r.coeffs[8 * i + 2] &= 0x1fff;

    r.coeffs[8 * i + 3] = a[aOffset + 13 * i + 4] >> 7;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 5] << 1;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 6] << 9;
    r.coeffs[8 * i + 3] &= 0x1fff;

    r.coeffs[8 * i + 4] = a[aOffset + 13 * i + 6] >> 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 7] << 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 8] << 12;
    r.coeffs[8 * i + 4] &= 0x1fff;

    r.coeffs[8 * i + 5] = a[aOffset + 13 * i + 8] >> 1;
    r.coeffs[8 * i + 5] |= a[aOffset + 13 * i + 9] << 7;
    r.coeffs[8 * i + 5] &= 0x1fff;

    r.coeffs[8 * i + 6] = a[aOffset + 13 * i + 9] >> 6;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 10] << 2;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 11] << 10;
    r.coeffs[8 * i + 6] &= 0x1fff;

    r.coeffs[8 * i + 7] = a[aOffset + 13 * i + 11] >> 3;
    r.coeffs[8 * i + 7] |= a[aOffset + 13 * i + 12] << 5;
    r.coeffs[8 * i + 7] &= 0x1fff;

    r.coeffs[8 * i] = (1 << (D - 1)) - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = (1 << (D - 1)) - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = (1 << (D - 1)) - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = (1 << (D - 1)) - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = (1 << (D - 1)) - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = (1 << (D - 1)) - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = (1 << (D - 1)) - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = (1 << (D - 1)) - r.coeffs[8 * i + 7];
  }
}

export function polyZPack(rP, rOffset, a) {
  const t = new Uint32Array(4);
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    t[0] = GAMMA1 - a.coeffs[2 * i];
    t[1] = GAMMA1 - a.coeffs[2 * i + 1];

    r[rOffset + 5 * i] = t[0]; // eslint-disable-line prefer-destructuring
    r[rOffset + 5 * i + 1] = t[0] >> 8;
    r[rOffset + 5 * i + 2] = t[0] >> 16;
    r[rOffset + 5 * i + 2] |= t[1] << 4;
    r[rOffset + 5 * i + 3] = t[1] >> 4;
    r[rOffset + 5 * i + 4] = t[1] >> 12;
  }
}

export function polyW1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r[rOffset + i] = a.coeffs[2 * i] | (a.coeffs[2 * i + 1] << 4);
  }
}
