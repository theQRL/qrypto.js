import { expect } from 'chai';
import { packSig, unpackSig } from '../src/packing.js';
import { PolyVecK, PolyVecL } from '../src/polyvec.js';
import { K, N, OMEGA, CTILDEBytes, CryptoBytes } from '../src/const.js';

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
