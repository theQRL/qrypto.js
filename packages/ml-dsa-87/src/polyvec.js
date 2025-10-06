import {
  Poly,
  polyAdd,
  polyCAddQ,
  polyChkNorm,
  polyDecompose,
  polyInvNTTToMont,
  polyMakeHint,
  polyNTT,
  polyPointWiseMontgomery,
  polyPower2round,
  polyReduce,
  polyShiftL,
  polySub,
  polyUniform,
  polyUniformEta,
  polyUniformGamma1,
  polyUseHint,
  polyW1Pack,
} from './poly.js';
import { CRHBytes, K, L, PolyW1PackedBytes, SeedBytes } from './const.js';

export class PolyVecK {
  constructor() {
    this.vec = new Array(K).fill().map(() => new Poly());
  }
}

export class PolyVecL {
  constructor() {
    this.vec = new Array(L).fill().map(() => new Poly());
  }

  copy(polyVecL) {
    for (let i = L - 1; i >= 0; i--) {
      this.vec[i].copy(polyVecL.vec[i]);
    }
  }
}

export function polyVecMatrixExpand(mat, rho) {
  if (rho.length !== SeedBytes) {
    throw new Error(`invalid rho length ${rho.length} | Expected length ${SeedBytes}`);
  }
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < L; ++j) {
      polyUniform(mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

export function polyVecMatrixPointWiseMontgomery(t, mat, v) {
  for (let i = 0; i < K; ++i) {
    polyVecLPointWiseAccMontgomery(t.vec[i], mat[i], v); // eslint-disable-line no-use-before-define
  }
}

export function polyVecLUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

export function polyVecLUniformGamma1(v, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformGamma1(v.vec[i], seed, L * nonce + i);
  }
}

export function polyVecLReduce(v) {
  for (let i = 0; i < L; i++) {
    polyReduce(v.vec[i]);
  }
}

export function polyVecLAdd(w, u, v) {
  for (let i = 0; i < L; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

export function polyVecLNTT(v) {
  for (let i = 0; i < L; ++i) {
    polyNTT(v.vec[i]);
  }
}

export function polyVecLInvNTTToMont(v) {
  for (let i = 0; i < L; ++i) {
    polyInvNTTToMont(v.vec[i]);
  }
}

export function polyVecLPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < L; ++i) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

export function polyVecLPointWiseAccMontgomery(w, u, v) {
  const t = new Poly();
  polyPointWiseMontgomery(w, u.vec[0], v.vec[0]);
  for (let i = 1; i < L; i++) {
    polyPointWiseMontgomery(t, u.vec[i], v.vec[i]);
    polyAdd(w, w, t);
  }
}

export function polyVecLChkNorm(v, bound) {
  for (let i = 0; i < L; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

export function polyVecKUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  for (let i = 0; i < K; ++i) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

export function polyVecKReduce(v) {
  for (let i = 0; i < K; ++i) {
    polyReduce(v.vec[i]);
  }
}

export function polyVecKCAddQ(v) {
  for (let i = 0; i < K; ++i) {
    polyCAddQ(v.vec[i]);
  }
}

export function polyVecKAdd(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

export function polyVecKSub(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polySub(w.vec[i], u.vec[i], v.vec[i]);
  }
}

export function polyVecKShiftL(v) {
  for (let i = 0; i < K; ++i) {
    polyShiftL(v.vec[i]);
  }
}

export function polyVecKNTT(v) {
  for (let i = 0; i < K; i++) {
    polyNTT(v.vec[i]);
  }
}

export function polyVecKInvNTTToMont(v) {
  for (let i = 0; i < K; i++) {
    polyInvNTTToMont(v.vec[i]);
  }
}

export function polyVecKPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < K; i++) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

export function polyVecKChkNorm(v, bound) {
  for (let i = 0; i < K; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

export function polyVecKPower2round(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyPower2round(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

export function polyVecKDecompose(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyDecompose(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

export function polyVecKMakeHint(h, v0, v1) {
  let s = 0;
  for (let i = 0; i < K; i++) {
    s += polyMakeHint(h.vec[i], v0.vec[i], v1.vec[i]);
  }
  return s;
}

export function polyVecKUseHint(w, u, h) {
  for (let i = 0; i < K; ++i) {
    polyUseHint(w.vec[i], u.vec[i], h.vec[i]);
  }
}

export function polyVecKPackW1(r, w1) {
  for (let i = 0; i < K; ++i) {
    polyW1Pack(r, i * PolyW1PackedBytes, w1.vec[i]);
  }
}
