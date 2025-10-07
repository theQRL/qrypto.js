import pkg from 'randombytes'; // eslint-disable-line import/no-extraneous-dependencies
import { SHAKE } from 'sha3'; // eslint-disable-line import/no-extraneous-dependencies

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
  TRBytes,
  RNDBytes,
  CTILDEBytes,
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

const randomBytes = pkg;
// Default signing context
const DEFAULT_CTX = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]); // "ZOND"

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

  // Expand seed -> rho(32), rhoPrime(64), key(32) with domain sep [K, L]
  const seed = passedSeed || randomBytes(SeedBytes);

  const state = new SHAKE(256);
  let outputLength = 2 * SeedBytes + CRHBytes;
  state.update(seed);
  state.update(Uint8Array.from([K, L]));
  const seedBuf = state.digest({ buffer: Buffer.alloc(outputLength) });
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

  // Compute tr = SHAKE256(pk) (64 bytes) and write secret key
  const hasher = new SHAKE(256);
  outputLength = TRBytes;
  hasher.update(Buffer.from(pk, 'hex'));
  const tr = new Uint8Array(hasher.digest({ buffer: Buffer.alloc(outputLength) }));
  packSk(sk, rho, tr, key, t0, s1, s2);

  return seed;
}

export function cryptoSignSignature(sig, m, sk, randomizedSigning, ctx = DEFAULT_CTX) {
  if (ctx.length > 255) throw new Error(`invalid context length: ${ctx.length} (max 255)`)
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const rho = new Uint8Array(SeedBytes);
  const tr = new Uint8Array(TRBytes);
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
  
  // pre = 0x00 || len(ctx) || ctx
  const pre = new Uint8Array(2 + ctx.length);
  pre[0] = 0; 
  pre[1] = ctx.length; 
  pre.set(ctx, 2);
  // mu = SHAKE256(tr || pre || m)
  state = new SHAKE(256);
  let outputLength = CRHBytes;
  state.update(Buffer.from(tr, 'hex'));
  state.update(Buffer.from(pre, 'hex'));
  state.update(Buffer.from(m, 'hex'));
  const mu = new Uint8Array(state.digest({ buffer: Buffer.alloc(outputLength) }))

  // rhoPrime = SHAKE256(key || rnd || mu)
  const rnd = randomizedSigning ? randomBytes(RNDBytes) : new Uint8Array(RNDBytes);
  state = new SHAKE(256);
  state.update(Buffer.from(key, 'hex'));
  state.update(Buffer.from(rnd, 'hex'));
  state.update(Buffer.from(mu, 'hex'));
  rhoPrime.set(state.digest({ buffer: Buffer.alloc(CRHBytes) }));

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

    // ctilde = SHAKE256(mu || w1_packed) (64 bytes)
    state = new SHAKE(256);
    outputLength = CTILDEBytes;
    state.update(Buffer.from(mu, 'hex'));
    state.update(Buffer.from(sig.slice(0, K * PolyW1PackedBytes)), 'hex');
    const ctilde = new Uint8Array(state.digest({ buffer: Buffer.alloc(outputLength) }));

    polyChallenge(cp, ctilde);
    polyNTT(cp);

    // Compute z, reject if it reveals secret
    polyVecLPointWisePolyMontgomery(z, cp, s1);
    polyVecLInvNTTToMont(z);
    polyVecLAdd(z, z, y);
    polyVecLReduce(z);
    if (polyVecLChkNorm(z, GAMMA1 - BETA) !== 0) {
      continue; // eslint-disable-line no-continue
    }

    polyVecKPointWisePolyMontgomery(h, cp, s2);
    polyVecKInvNTTToMont(h);
    polyVecKSub(w0, w0, h);
    polyVecKReduce(w0);
    if (polyVecKChkNorm(w0, GAMMA2 - BETA) !== 0) {
      continue; // eslint-disable-line no-continue
    }

    polyVecKPointWisePolyMontgomery(h, cp, t0);
    polyVecKInvNTTToMont(h);
    polyVecKReduce(h);
    if (polyVecKChkNorm(h, GAMMA2) !== 0) {
      continue; // eslint-disable-line no-continue
    }

    polyVecKAdd(w0, w0, h);
    const n = polyVecKMakeHint(h, w0, w1);
    if (n > OMEGA) {
      continue; // eslint-disable-line no-continue
    }

    packSig(sig, ctilde, z, h);
    return 0;
  }
}

export function cryptoSign(msg, sk, randomizedSigning, ctx = DEFAULT_CTX) {
  const sm = new Uint8Array(CryptoBytes + msg.length);
  const mLen = msg.length;
  for (let i = 0; i < mLen; ++i) {
    sm[CryptoBytes + mLen - 1 - i] = msg[mLen - 1 - i];
  }
  const result = cryptoSignSignature(sm, msg, sk, randomizedSigning, ctx);

  if (result !== 0) {
    throw new Error('failed to sign');
  }
  return sm;
}

export function cryptoSignVerify(sig, m, pk, ctx = DEFAULT_CTX) {
  if (ctx.length > 255) return false;
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(CTILDEBytes);
  const c2 = new Uint8Array(CTILDEBytes);
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

  /* Compute mu = SHAKE256(tr || pre || m) with tr = SHAKE256(pk) */
  let state = new SHAKE(256);
  let outputLength = TRBytes;
  state.update(pk);
  const tr = new Uint8Array(state.digest({ buffer: Buffer.alloc(outputLength) }));
  const pre = new Uint8Array(2 + ctx.length); 
  pre[0] = 0;
  pre[1] = ctx.length;
  pre.set(ctx, 2);
  
  state = new SHAKE(256);
  outputLength = CRHBytes;
  state.update(Buffer.from(tr, 'hex'));
  state.update(Buffer.from(pre, 'hex'));
  state.update(Buffer.from(m, 'hex'));
  mu.set(state.digest({ buffer: Buffer.alloc(outputLength) }));

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
  state = new SHAKE(256);
  outputLength = CTILDEBytes;
  state.update(Buffer.from(mu, 'hex'));
  state.update(Buffer.from(buf, 'hex'));
  c2.set(state.digest({ buffer: Buffer.alloc(outputLength) }));

  for (i = 0; i < CTILDEBytes; ++i) if (c[i] !== c2[i]) return false;
  return true;
}

export function cryptoSignOpen(sm, pk, ctx = DEFAULT_CTX) {
  if (sm.length < CryptoBytes) {
    return undefined;
  }

  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk, ctx)) {
    return undefined;
  }

  return msg;
}