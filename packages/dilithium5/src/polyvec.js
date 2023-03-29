const {
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
} = require('./poly.js');
const { CRHBytes, K, L, PolyW1PackedBytes, SeedBytes } = require('./const.js');

class PolyVecK {
  constructor() {
    this.vec = new Array(K).fill().map((_) => new Poly());
  }
}

class PolyVecL {
  constructor() {
    this.vec = new Array(L).fill().map((_) => new Poly());
  }

  copy(polyVecL) {
    for (let i = L - 1; i >= 0; i--) {
      this.vec[i].copy(polyVecL.vec[i]);
    }
  }
}

function polyVecMatrixExpand(mat, rho) {
  if (rho.length !== SeedBytes) {
    throw new Error(`invalid rho length ${rho.length} | Expected length ${SeedBytes}`);
  }
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < L; ++j) {
      polyUniform(mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

function polyVecMatrixPointWiseMontgomery(t, mat, v) {
  for (let i = 0; i < K; ++i) {
    polyVecLPointWiseAccMontgomery(t.vec[i], mat[i], v);
  }
}

function polyVecLUniformEta(v, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecLUniformGamma1(v, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformGamma1(v.vec[i], seed, L * nonce + i);
  }
}

function polyVecLReduce(v) {
  for (let i = 0; i < L; i++) {
    polyReduce(v.vec[i]);
  }
}

function polyVecLAdd(w, u, v) {
  for (let i = 0; i < L; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecLNTT(v) {
  for (let i = 0; i < L; ++i) {
    polyNTT(v.vec[i]);
  }
}

function polyVecLInvNTTToMont(v) {
  for (let i = 0; i < L; ++i) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecLPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < L; ++i) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecLPointWiseAccMontgomery(w, u, v) {
  const t = new Poly();
  polyPointWiseMontgomery(w, u.vec[0], v.vec[0]);
  for (let i = 1; i < L; i++) {
    polyPointWiseMontgomery(t, u.vec[i], v.vec[i]);
    polyAdd(w, w, t);
  }
}

function polyVecLChkNorm(v, bound) {
  for (let i = 0; i < L; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKUniformEta(v, seed, nonce) {
  for (let i = 0; i < K; ++i) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecKReduce(v) {
  for (let i = 0; i < K; ++i) {
    polyReduce(v.vec[i]);
  }
}

function polyVecKCAddQ(v) {
  for (let i = 0; i < K; ++i) {
    polyCAddQ(v.vec[i]);
  }
}

function polyVecKAdd(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKSub(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polySub(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKShiftL(v) {
  for (let i = 0; i < K; ++i) {
    polyShiftL(v.vec[i]);
  }
}

function polyVecKNTT(v) {
  for (let i = 0; i < K; i++) {
    polyNTT(v.vec[i]);
  }
}

function polyVecKInvNTTToMont(v) {
  for (let i = 0; i < K; i++) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecKPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < K; i++) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecKChkNorm(v, bound) {
  for (let i = 0; i < K; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKPower2round(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyPower2round(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKDecompose(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyDecompose(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKMakeHint(h, v0, v1) {
  let s = 0;
  for (let i = 0; i < K; i++) {
    s += polyMakeHint(h.vec[i], v0.vec[i], v1.vec[i]);
  }
  return s;
}

function polyVecKUseHint(w, u, h) {
  for (let i = 0; i < K; ++i) {
    polyUseHint(w.vec[i], u.vec[i], h.vec[i]);
  }
}

function polyVecKPackW1(r, w1) {
  for (let i = 0; i < K; ++i) {
    polyW1Pack(r, i * PolyW1PackedBytes, w1.vec[i]);
  }
}

module.exports = {
  polyVecLUniformEta,
  polyVecLUniformGamma1,
  polyVecLReduce,
  polyVecLAdd,
  polyVecLNTT,
  polyVecLInvNTTToMont,
  polyVecLPointWisePolyMontgomery,
  polyVecLPointWiseAccMontgomery,
  polyVecLChkNorm,
  polyVecKUniformEta,
  polyVecKReduce,
  polyVecKCAddQ,
  polyVecKAdd,
  polyVecKSub,
  polyVecKShiftL,
  polyVecKNTT,
  polyVecKInvNTTToMont,
  polyVecKPointWisePolyMontgomery,
  polyVecKChkNorm,
  polyVecKPower2round,
  polyVecKDecompose,
  polyVecKMakeHint,
  polyVecKUseHint,
  polyVecKPackW1,
  polyVecMatrixPointWiseMontgomery,
  PolyVecL,
  PolyVecK,
  polyVecMatrixExpand,
};
