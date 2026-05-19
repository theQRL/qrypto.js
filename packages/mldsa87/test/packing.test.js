import { expect } from 'chai';
import { packSig, unpackPk, unpackSig, unpackSk } from '../src/packing.js';
import { PolyVecK, PolyVecL } from '../src/polyvec.js';
import {
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CTILDEBytes,
  K,
  N,
  OMEGA,
  SeedBytes,
  TRBytes,
} from '../src/const.js';

describe('packSig hint validation (FIND-009)', function () {
  this.timeout(10000);

  it('should accept valid binary hints within OMEGA budget', function () {
    const sig = new Uint8Array(CryptoBytes);
    const ctilde = new Uint8Array(CTILDEBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    h.vec[0].coeffs[0] = 1;
    h.vec[0].coeffs[5] = 1;
    h.vec[1].coeffs[3] = 1;
    packSig(sig, ctilde, z, h);

    const c2 = new Uint8Array(CTILDEBytes);
    const z2 = new PolyVecL();
    const h2 = new PolyVecK();
    expect(unpackSig(c2, z2, h2, sig)).to.equal(0);
  });

  it('should accept all-zero hints', function () {
    const sig = new Uint8Array(CryptoBytes);
    const ctilde = new Uint8Array(CTILDEBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    packSig(sig, ctilde, z, h);

    const c2 = new Uint8Array(CTILDEBytes);
    const z2 = new PolyVecL();
    const h2 = new PolyVecK();
    expect(unpackSig(c2, z2, h2, sig)).to.equal(0);
  });

  it('should accept exactly OMEGA hints', function () {
    const sig = new Uint8Array(CryptoBytes);
    const ctilde = new Uint8Array(CTILDEBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    // Spread OMEGA hints across polynomials
    let placed = 0;
    for (let i = 0; i < K && placed < OMEGA; i++) {
      for (let j = 0; j < N && placed < OMEGA; j++) {
        h.vec[i].coeffs[j] = 1;
        placed++;
      }
    }
    packSig(sig, ctilde, z, h);

    const c2 = new Uint8Array(CTILDEBytes);
    const z2 = new PolyVecL();
    const h2 = new PolyVecK();
    expect(unpackSig(c2, z2, h2, sig)).to.equal(0);
  });

  it('should throw on non-binary hint coefficients', function () {
    const sig = new Uint8Array(CryptoBytes);
    const ctilde = new Uint8Array(CTILDEBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    h.vec[0].coeffs[0] = 5;
    expect(() => packSig(sig, ctilde, z, h)).to.throw(/binary/);
  });

  it('should throw when hint count exceeds OMEGA', function () {
    const sig = new Uint8Array(CryptoBytes);
    const ctilde = new Uint8Array(CTILDEBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    for (let i = 0; i < K; i++) {
      for (let j = 0; j < 20; j++) {
        h.vec[i].coeffs[j] = 1;
      }
    }
    expect(() => packSig(sig, ctilde, z, h)).to.throw(/OMEGA/);
  });
});

// Defense-in-depth: unpackPk / unpackSk are internal helpers whose
// callers (cryptoSignVerify / cryptoSignSignatureInternal) already
// validate pk / sk lengths. The internal length guards are reachable
// only via direct programmatic use of the helpers, but they are the
// last line of defense if a refactor ever removes the upstream check —
// so we exercise them explicitly.
describe('packing internal length guards (defense-in-depth)', () => {
  it('unpackPk rejects wrong-length pk', () => {
    const rho = new Uint8Array(SeedBytes);
    const t1 = new PolyVecK();
    expect(() => unpackPk(rho, t1, new Uint8Array(CryptoPublicKeyBytes - 1)))
      .to.throw(`pk must be a Uint8Array of ${CryptoPublicKeyBytes} bytes`);
  });

  it('unpackPk rejects non-Uint8Array pk', () => {
    const rho = new Uint8Array(SeedBytes);
    const t1 = new PolyVecK();
    expect(() => unpackPk(rho, t1, 'not-bytes'))
      .to.throw(`pk must be a Uint8Array of ${CryptoPublicKeyBytes} bytes`);
  });

  it('unpackSk rejects wrong-length sk', () => {
    const rho = new Uint8Array(SeedBytes);
    const tr = new Uint8Array(TRBytes);
    const key = new Uint8Array(SeedBytes);
    const t0 = new PolyVecK();
    const s1 = new PolyVecL();
    const s2 = new PolyVecK();
    expect(() => unpackSk(rho, tr, key, t0, s1, s2, new Uint8Array(CryptoSecretKeyBytes - 1)))
      .to.throw(`sk must be a Uint8Array of ${CryptoSecretKeyBytes} bytes`);
  });

  it('unpackSk rejects non-Uint8Array sk', () => {
    const rho = new Uint8Array(SeedBytes);
    const tr = new Uint8Array(TRBytes);
    const key = new Uint8Array(SeedBytes);
    const t0 = new PolyVecK();
    const s1 = new PolyVecL();
    const s2 = new PolyVecK();
    expect(() => unpackSk(rho, tr, key, t0, s1, s2, null))
      .to.throw(`sk must be a Uint8Array of ${CryptoSecretKeyBytes} bytes`);
  });
});
