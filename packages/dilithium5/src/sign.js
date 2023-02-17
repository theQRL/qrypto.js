import { createHash, randomBytes } from 'crypto';
import {
  PolyVecK,
  polyVecKAdd,
  polyVecKCAddQ,
  polyVecKChkNorm,
  polyVecKDecompose,
  polyVecKInvNTTToMont,
  polyVecKMakeHint,
  polyVecKNTT,
  polyVecKPackW1,
  polyVecKPointWisePolyMontgomery,
  polyVecKPower2round,
  polyVecKReduce,
  polyVecKShiftL,
  polyVecKSub,
  polyVecKUniformEta,
  polyVecKUseHint,
  PolyVecL,
  polyVecLAdd,
  polyVecLChkNorm,
  polyVecLInvNTTToMont,
  polyVecLNTT,
  polyVecLPointWisePolyMontgomery,
  polyVecLReduce,
  polyVecLUniformEta,
  polyVecLUniformGamma1,
  polyVecMatrixExpand,
  polyVecMatrixPointWiseMontgomery,
} from './polyvec.js';
import {
  BETA,
  CRHBytes,
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  GAMMA1,
  GAMMA2,
  K,
  L,
  OMEGA,
  PolyW1PackedBytes,
  SeedBytes,
} from './const.js';
import { Poly, polyChallenge, polyNTT } from './poly.js';
import { packPk, packSig, packSk, unpackPk, unpackSig, unpackSk } from './packing.js';

export function cryptoSignKeypair(passedSeed, pk, sk) {
  try {
    if (pk.length !== CryptoPublicKeyBytes) {
      throw new Error(`invalid pk length ${pk.length} | Expected length ${CryptoPublicKeyBytes}`);
    }
    if (sk.length !== CryptoSecretKeyBytes) {
      throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error(`pk/sk cannot be null`);
    } else {
      throw new Error(`${e.message}`);
    }
  }
  // eslint-disable-next-line no-unused-vars
  const mat = new Array(K).fill().map((_) => new PolyVecL());
  const s1 = new PolyVecL();
  const s2 = new PolyVecK();
  const t1 = new PolyVecK();
  const t0 = new PolyVecK();

  // Get randomness for rho, rhoPrime and key
  const seed = passedSeed || new Uint8Array(randomBytes(SeedBytes));

  const state = createHash('shake256', { outputLength: 2 * SeedBytes + CRHBytes });
  state.update(seed);
  const seedBuf = state.digest();
  const rho = seedBuf.slice(0, SeedBytes);
  const rhoPrime = seedBuf.slice(SeedBytes, SeedBytes + CRHBytes);
  const key = seedBuf.slice(SeedBytes + CRHBytes);

  // Expand matrix
  polyVecMatrixExpand(mat, rho);

  // Sample short vectors s1 and s2
  polyVecLUniformEta(s1, rhoPrime, 0);
  polyVecKUniformEta(s2, rhoPrime, L);

  // Matrix-vector multiplication
  const s1hat = new PolyVecL();
  s1hat.copy(s1);
  polyVecLNTT(s1hat);
  polyVecMatrixPointWiseMontgomery(t1, mat, s1hat);
  polyVecKReduce(t1);
  polyVecKInvNTTToMont(t1);

  // Add error vector s2
  polyVecKAdd(t1, t1, s2);

  // Extract t1 and write public key
  polyVecKCAddQ(t1);
  polyVecKPower2round(t1, t0, t1);
  packPk(pk, rho, t1);

  // Compute H(rho, t1) and write secret key
  const hasher = createHash('shake256', { outputLength: SeedBytes });
  hasher.update(pk);
  const tr = new Uint8Array(hasher.digest());
  packSk(sk, rho, tr, key, t0, s1, s2);

  return seed;
}

export function cryptoSignSignature(sig, m, sk, randomizedSigning) {
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const rho = new Uint8Array(SeedBytes);
  const tr = new Uint8Array(SeedBytes);
  const key = new Uint8Array(SeedBytes);
  let rhoPrime = new Uint8Array(CRHBytes);
  let nonce = 0;
  let state = null;
  const mat = Array(K)
    .fill()
    // eslint-disable-next-line no-unused-vars
    .map((_) => new PolyVecL());
  const s1 = new PolyVecL();
  const y = new PolyVecL();
  const z = new PolyVecL();
  const t0 = new PolyVecK();
  const s2 = new PolyVecK();
  const w1 = new PolyVecK();
  const w0 = new PolyVecK();
  const h = new PolyVecK();
  const cp = new Poly();

  unpackSk(rho, tr, key, t0, s1, s2, sk);

  state = createHash('shake256', { outputLength: CRHBytes });
  state.update(tr);
  state.update(m);
  const mu = new Uint8Array(state.digest());

  if (randomizedSigning) rhoPrime = new Uint8Array(randomBytes(CRHBytes));
  else {
    state = createHash('shake256', { outputLength: CRHBytes });
    state.update(key);
    state.update(mu);
    rhoPrime.set(state.digest());
  }

  polyVecMatrixExpand(mat, rho);
  polyVecLNTT(s1);
  polyVecKNTT(s2);
  polyVecKNTT(t0);

  // eslint-disable-next-line no-constant-condition
  while (true) {
    polyVecLUniformGamma1(y, rhoPrime, nonce++);
    // Matrix-vector multiplication
    z.copy(y);
    polyVecLNTT(z);
    polyVecMatrixPointWiseMontgomery(w1, mat, z);
    polyVecKReduce(w1);
    polyVecKInvNTTToMont(w1);

    // Decompose w and call the random oracle
    polyVecKCAddQ(w1);
    polyVecKDecompose(w1, w0, w1);
    polyVecKPackW1(sig, w1);

    state = createHash('shake256', { outputLength: SeedBytes });
    state.update(mu);
    state.update(sig.slice(0, K * PolyW1PackedBytes));
    sig.set(state.digest());

    polyChallenge(cp, sig);
    polyNTT(cp);

    // Compute z, reject if it reveals secret
    polyVecLPointWisePolyMontgomery(z, cp, s1);
    polyVecLInvNTTToMont(z);
    polyVecLAdd(z, z, y);
    polyVecLReduce(z);
    if (polyVecLChkNorm(z, GAMMA1 - BETA) !== 0) {
      continue;
    }

    polyVecKPointWisePolyMontgomery(h, cp, s2);
    polyVecKInvNTTToMont(h);
    polyVecKSub(w0, w0, h);
    polyVecKReduce(w0);
    if (polyVecKChkNorm(w0, GAMMA2 - BETA) !== 0) {
      continue;
    }

    polyVecKPointWisePolyMontgomery(h, cp, t0);
    polyVecKInvNTTToMont(h);
    polyVecKReduce(h);
    if (polyVecKChkNorm(h, GAMMA2) !== 0) {
      continue;
    }

    polyVecKAdd(w0, w0, h);
    const n = polyVecKMakeHint(h, w0, w1);
    if (n > OMEGA) {
      continue;
    }

    packSig(sig, sig, z, h);
    return 0;
  }
}

export function cryptoSign(msg, sk, randomizedSigning) {
  const sm = new Uint8Array(CryptoBytes + msg.length);
  const mLen = msg.length;
  for (let i = 0; i < mLen; ++i) {
    sm[CryptoBytes + mLen - 1 - i] = msg[mLen - 1 - i];
  }
  const result = cryptoSignSignature(sm, msg, sk, randomizedSigning);

  if (result !== 0) {
    throw new Error('failed to sign');
  }
  return sm;
}

export function cryptoSignVerify(sig, m, pk) {
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(SeedBytes);
  const c2 = new Uint8Array(SeedBytes);
  const cp = new Poly();
  // eslint-disable-next-line no-unused-vars
  const mat = new Array(K).fill().map((_) => new PolyVecL());
  const z = new PolyVecL();
  const t1 = new PolyVecK();
  const w1 = new PolyVecK();
  const h = new PolyVecK();

  if (sig.length !== CryptoBytes) {
    return false;
  }
  if (pk.length !== CryptoPublicKeyBytes) {
    return false;
  }

  unpackPk(rho, t1, pk);
  if (unpackSig(c, z, h, sig)) {
    return false;
  }
  if (polyVecLChkNorm(z, GAMMA1 - BETA)) {
    return false;
  }

  /* Compute CRH(H(rho, t1), msg) */
  let state = createHash('shake256', { outputLength: SeedBytes });
  state.update(pk.slice(0, CryptoPublicKeyBytes));
  mu.set(state.digest());

  state = createHash('shake256', { outputLength: CRHBytes });
  state.update(mu.slice(0, SeedBytes));
  state.update(m);
  mu.set(state.digest());

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  polyChallenge(cp, c);
  polyVecMatrixExpand(mat, rho);

  polyVecLNTT(z);
  polyVecMatrixPointWiseMontgomery(w1, mat, z);

  polyNTT(cp);
  polyVecKShiftL(t1);
  polyVecKNTT(t1);
  polyVecKPointWisePolyMontgomery(t1, cp, t1);

  polyVecKSub(w1, w1, t1);
  polyVecKReduce(w1);
  polyVecKInvNTTToMont(w1);

  /* Reconstruct w1 */
  polyVecKCAddQ(w1);
  polyVecKUseHint(w1, w1, h);
  polyVecKPackW1(buf, w1);

  /* Call random oracle and verify challenge */
  state = createHash('shake256', { outputLength: SeedBytes });
  state.update(mu);
  state.update(buf);
  c2.set(state.digest());

  for (i = 0; i < SeedBytes; ++i) if (c[i] !== c2[i]) return false;
  return true;
}

export function cryptoSignOpen(sm, pk) {
  if (sm.length < CryptoBytes) {
    return undefined;
  }

  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk)) {
    return undefined;
  }

  return msg;
}
