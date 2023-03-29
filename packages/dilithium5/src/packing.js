const {
  K,
  L,
  N,
  OMEGA,
  PolyETAPackedBytes,
  PolyT0PackedBytes,
  PolyT1PackedBytes,
  PolyZPackedBytes,
  SeedBytes,
} = require('./const.js');
const {
  polyEtaPack,
  polyEtaUnpack,
  polyT0Pack,
  polyT0Unpack,
  polyT1Pack,
  polyT1Unpack,
  polyZPack,
  polyZUnpack,
} = require('./poly.js');

function packPk(pkp, rho, t1) {
  const pk = pkp;
  for (let i = 0; i < SeedBytes; ++i) {
    pk[i] = rho[i];
  }
  for (let i = 0; i < K; ++i) {
    polyT1Pack(pk, SeedBytes + i * PolyT1PackedBytes, t1.vec[i]);
  }
}

function unpackPk(rhop, t1, pk) {
  const rho = rhop;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = pk[i];
  }

  for (let i = 0; i < K; ++i) {
    polyT1Unpack(t1.vec[i], pk, SeedBytes + i * PolyT1PackedBytes);
  }
}

function packSk(skp, rho, tr, key, t0, s1, s2) {
  let skOffset = 0;
  const sk = skp;
  for (let i = 0; i < SeedBytes; ++i) {
    sk[i] = rho[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    sk[skOffset + i] = key[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    sk[skOffset + i] = tr[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s1.vec[i]);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s2.vec[i]);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Pack(sk, skOffset + i * PolyT0PackedBytes, t0.vec[i]);
  }
}

function unpackSk(rhoP, trP, keyP, t0, s1, s2, sk) {
  let skOffset = 0;
  const rho = rhoP;
  const tr = trP;
  const key = keyP;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    key[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    tr[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaUnpack(s1.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaUnpack(s2.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Unpack(t0.vec[i], sk, skOffset + i * PolyT0PackedBytes);
  }
}

function packSig(sigP, c, z, h) {
  let sigOffset = 0;
  const sig = sigP;
  for (let i = 0; i < SeedBytes; ++i) {
    sig[i] = c[i];
  }
  sigOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyZPack(sig, sigOffset + i * PolyZPackedBytes, z.vec[i]);
  }
  sigOffset += L * PolyZPackedBytes;

  for (let i = 0; i < OMEGA + K; ++i) {
    sig[sigOffset + i] = 0;
  }

  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      if (h.vec[i].coeffs[j] !== 0) {
        sig[sigOffset + k++] = j;
      }
    }

    sig[sigOffset + OMEGA + i] = k;
  }
}

function unpackSig(cP, z, hP, sig) {
  let sigOffset = 0;
  const c = cP;
  const h = hP;
  for (let i = 0; i < SeedBytes; ++i) {
    c[i] = sig[i];
  }
  sigOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyZUnpack(z.vec[i], sig, sigOffset + i * PolyZPackedBytes);
  }
  sigOffset += L * PolyZPackedBytes;

  /* Decode h */
  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      h.vec[i].coeffs[j] = 0;
    }

    if (sig[sigOffset + OMEGA + i] < k || sig[sigOffset + OMEGA + i] > OMEGA) {
      return 1;
    }

    for (let j = k; j < sig[sigOffset + OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if (j > k && sig[sigOffset + j] <= sig[sigOffset + j - 1]) {
        return 1;
      }
      h.vec[i].coeffs[sig[sigOffset + j]] = 1;
    }

    k = sig[sigOffset + OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for (let j = k; j < OMEGA; ++j) {
    if (sig[sigOffset + j]) {
      return 1;
    }
  }

  return 0;
}

module.exports = {
  packPk,
  unpackPk,
  packSk,
  unpackSk,
  packSig,
  unpackSig,
};
