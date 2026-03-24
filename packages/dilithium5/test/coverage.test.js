import { expect } from 'chai';
import {
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  K,
  L,
  OMEGA,
  PolyZPackedBytes,
  Q,
  SeedBytes,
} from '../src/const.js';
import { unpackSig } from '../src/packing.js';
import { Poly, polyChallenge, polyChkNorm } from '../src/poly.js';
import { PolyVecK, PolyVecL, polyVecMatrixExpand } from '../src/polyvec.js';
import { cryptoSign, cryptoSignKeypair, cryptoSignOpen, cryptoSignSignature, cryptoSignVerify } from '../src/sign.js';
import { zeroize } from '../src/utils.js';

describe('coverage: polyChkNorm', () => {
  it('should reject when b is too large', () => {
    const poly = new Poly();
    const limit = Math.floor((Q - 1) / 8) + 1;
    expect(polyChkNorm(poly, limit)).to.equal(1);
  });

  it('should reject coefficients with large negative values beyond 2^30', () => {
    const poly = new Poly();
    poly.coeffs[0] = -1073741825; // -(2^30 + 1)
    expect(polyChkNorm(poly, 1)).to.equal(1);
  });
});

describe('coverage: polyChallenge seed validation', () => {
  it('should reject invalid seed length', () => {
    const c = new Poly();
    expect(() => polyChallenge(c, new Uint8Array(SeedBytes - 1))).to.throw('invalid seed length');
  });
});

describe('coverage: polyVecMatrixExpand', () => {
  it('should throw on invalid rho length', () => {
    const mat = new Array(K).fill().map(() => new PolyVecL());
    const rho = new Uint8Array(SeedBytes - 1);
    expect(() => polyVecMatrixExpand(mat, rho)).to.throw('invalid rho length');
  });
});

describe('coverage: cryptoSignKeypair seed validation', () => {
  it('should reject invalid seed length', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    const seed = new Uint8Array(SeedBytes - 1);
    expect(() => cryptoSignKeypair(seed, pk, sk)).to.throw('invalid seed length');
  });
});

describe('coverage: unpack buffer validation', () => {
  it('should reject undersized sig in unpackSig', () => {
    const c = new Uint8Array(SeedBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    expect(() => unpackSig(c, z, h, new Uint8Array(CryptoBytes - 1))).to.throw('sig must be a Uint8Array');
  });
});

describe('coverage: unpackSig validation', () => {
  it('should reject unordered hint indices', () => {
    const sig = new Uint8Array(CryptoBytes);
    const c = new Uint8Array(SeedBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    const sigOffset = SeedBytes + L * PolyZPackedBytes;

    sig[sigOffset + OMEGA] = 2;
    sig[sigOffset + 0] = 5;
    sig[sigOffset + 1] = 5;

    expect(unpackSig(c, z, h, sig)).to.equal(1);
  });

  it('should reject extra non-zero indices', () => {
    const sig = new Uint8Array(CryptoBytes);
    const c = new Uint8Array(SeedBytes);
    const z = new PolyVecL();
    const h = new PolyVecK();
    const sigOffset = SeedBytes + L * PolyZPackedBytes;

    sig[sigOffset + 0] = 1;

    expect(unpackSig(c, z, h, sig)).to.equal(1);
  });
});

describe('coverage: hex string validation', () => {
  it('should reject non-hex characters', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, 'zz', sk, false)).to.throw('hex string contains non-hex characters');
  });

  it('should reject whitespace-only strings', () => {
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, ' ', sk, false)).to.throw(
      'hex string must not have leading or trailing whitespace'
    );
  });

  it('should reject empty strings', () => {
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, '', sk, false)).to.throw('hex string must not be empty');
  });

  it('should reject strings with leading/trailing whitespace', () => {
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, ' aa ', sk, false)).to.throw(
      'hex string must not have leading or trailing whitespace'
    );
  });
});

describe('coverage: randomizedSigning type validation', () => {
  it('should reject non-boolean randomizedSigning', () => {
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, new Uint8Array([1]), sk, 'false')).to.throw(
      'randomizedSigning must be a boolean'
    );
  });
});

describe('coverage: Uint8Array type validation', () => {
  it('should reject non-Uint8Array sk in cryptoSignSignature', () => {
    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, new Uint8Array([1]), { length: CryptoSecretKeyBytes }, false)).to.throw(
      'sk must be a Uint8Array'
    );
  });

  it('should reject non-Uint8Array sig in cryptoSignSignature', () => {
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    expect(() => cryptoSignSignature(null, new Uint8Array([1]), sk, false)).to.throw('sig must be at least');
  });
});

describe('coverage: signing and verification branches', () => {
  it('should sign with randomizedSigning and verify', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    const msg = new Uint8Array([1, 2, 3]);
    const sig = new Uint8Array(CryptoBytes);
    cryptoSignSignature(sig, msg, sk, true);

    expect(cryptoSignVerify(sig, msg, pk)).to.equal(true);
  });

  it('should return false for invalid pk length', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    const msg = new Uint8Array([4, 5, 6]);
    const sig = new Uint8Array(CryptoBytes);
    cryptoSignSignature(sig, msg, sk, false);

    const shortPk = pk.slice(0, CryptoPublicKeyBytes - 1);
    expect(cryptoSignVerify(sig, msg, shortPk)).to.equal(false);
  });

  it('should return false for invalid message type', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    const msg = new Uint8Array([7, 8, 9]);
    const sig = new Uint8Array(CryptoBytes);
    cryptoSignSignature(sig, msg, sk, false);

    expect(cryptoSignVerify(sig, 123, pk)).to.equal(false);
  });

  it('should return undefined for short signed messages', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    cryptoSignKeypair(null, pk, new Uint8Array(CryptoSecretKeyBytes));

    const shortMessage = new Uint8Array(CryptoBytes - 1);
    expect(cryptoSignOpen(shortMessage, pk)).to.equal(undefined);
  });

  it('should return undefined for invalid signed messages', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    const msg = new Uint8Array([10, 11, 12]);
    const sig = new Uint8Array(CryptoBytes);
    cryptoSignSignature(sig, msg, sk, false);

    const sm = new Uint8Array(CryptoBytes + msg.length);
    sm.set(sig);
    sm.set(msg, CryptoBytes);
    sm[0] ^= 0x01;

    expect(cryptoSignOpen(sm, pk)).to.equal(undefined);
  });

  it('should throw on invalid message type in cryptoSignSignature', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, 123, sk, false)).to.throw('message must be Uint8Array or hex string');
  });

  it('should throw on invalid message type in cryptoSign', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(null, pk, sk);

    expect(() => cryptoSign(123, sk, false)).to.throw('message must be Uint8Array or hex string');
  });
});

describe('coverage: zeroize failure branch', () => {
  it('should throw if zeroize cannot clear the buffer', () => {
    const originalFill = Uint8Array.prototype.fill;
    try {
      Uint8Array.prototype.fill = function noop() {
        return this;
      };

      const buf = new Uint8Array([1]);
      expect(() => zeroize(buf)).to.throw('zeroize failed');
    } finally {
      Uint8Array.prototype.fill = originalFill;
    }
  });
});
