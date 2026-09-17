// validateSecretKey and the signing-side checks that go with it: an s1 or
// s2 coefficient outside [-ETA, ETA] is rejected before any work, and the
// rejection loop is bounded.
//
// Layout of a packed secret key:
//   rho (32) || K (32) || tr (64) || s1 (L*96) || s2 (K*96) || t0 (K*416)
// s1 and s2 coefficients are 3-bit fields holding ETA - v, packed eight per
// three bytes little-endian, so 0..2*ETA are the encodings key generation
// writes and 5, 6, 7 decode to -3, -4, -5. t0 coefficients are 13-bit fields
// holding 2^(D-1) - v; every value decodes into the Power2Round range.

import { expect } from 'chai';

import {
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  ETA,
  K,
  L,
  N,
  PolyETAPackedBytes,
  PolyT0PackedBytes,
  SeedBytes,
  TRBytes,
} from '../src/const.js';
import { Poly, polyT0Pack } from '../src/poly.js';
import {
  cryptoSign,
  cryptoSignDeterministic,
  cryptoSignKeypair,
  cryptoSignSignature,
  cryptoSignSignatureDeterministic,
  cryptoSignVerify,
  validateSecretKey,
} from '../src/sign.js';

const S1_OFFSET = 2 * SeedBytes + TRBytes;
const S2_OFFSET = S1_OFFSET + L * PolyETAPackedBytes;
const T0_OFFSET = S2_OFFSET + K * PolyETAPackedBytes;
const CTX = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]);
const MESSAGE = new TextEncoder().encode('secret key validation');
const OK = { ok: true };
const BAD_TYPE = { ok: false, reason: 'invalid-sk-type' };
const BAD_LENGTH = { ok: false, reason: 'invalid-sk-length' };
const BAD_ENCODING = { ok: false, reason: 'invalid-sk-encoding' };
const VALID_FIELDS = [0, 1, 2, 3, 4]; // decode to ETA .. -ETA
const INVALID_FIELDS = [5, 6, 7]; // decode to -3, -4, -5

function keypair(seedByte = 0x42) {
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  cryptoSignKeypair(new Uint8Array(SeedBytes).fill(seedByte), pk, sk);
  return { pk, sk };
}

// Overwrite the 3-bit field of coefficient `index` (0..N-1) of the eta-packed
// polynomial starting at `offset`. Field k occupies bits [3k, 3k+2] of the
// little-endian bit stream, so it spans at most two bytes.
function setEtaField(sk, offset, index, field) {
  const bit = 3 * index;
  const byte = offset + (bit >> 3);
  const shift = bit & 7;
  let word = sk[byte] | (sk[byte + 1] << 8);
  word &= ~(7 << shift);
  word |= field << shift;
  sk[byte] = word & 0xff;
  sk[byte + 1] = (word >> 8) & 0xff;
}

function withEtaField(sk, offset, index, field) {
  const copy = Uint8Array.from(sk);
  setEtaField(copy, offset, index, field);
  return copy;
}

describe('validateSecretKey', function () {
  const { pk, sk } = keypair();

  it('accepts a generated key', function () {
    expect(validateSecretKey(sk)).to.deep.equal(OK);
  });

  it('returns invalid-sk-type for anything that is not a Uint8Array', function () {
    for (const bad of [null, undefined, 'a'.repeat(CryptoSecretKeyBytes), Array.from(sk), sk.buffer, {}, 42]) {
      expect(validateSecretKey(bad)).to.deep.equal(BAD_TYPE);
    }
  });

  it('returns invalid-sk-length for a Uint8Array of the wrong length', function () {
    for (const len of [0, 1, CryptoSecretKeyBytes - 1, CryptoSecretKeyBytes + 1, CryptoPublicKeyBytes]) {
      expect(validateSecretKey(new Uint8Array(len))).to.deep.equal(BAD_LENGTH);
    }
  });

  it('accepts every encoding 0..2*ETA and rejects 5, 6, 7 at the corners of s1 and s2', function () {
    expect(2 * ETA).to.equal(4);
    const corners = [
      [S1_OFFSET, 0],
      [S1_OFFSET + (L - 1) * PolyETAPackedBytes, N - 1],
      [S2_OFFSET, 0],
      [S2_OFFSET + (K - 1) * PolyETAPackedBytes, N - 1],
    ];
    for (const [offset, index] of corners) {
      for (const field of VALID_FIELDS) {
        expect(validateSecretKey(withEtaField(sk, offset, index, field)), `field ${field}`).to.deep.equal(OK);
      }
      for (const field of INVALID_FIELDS) {
        expect(validateSecretKey(withEtaField(sk, offset, index, field)), `field ${field}`).to.deep.equal(BAD_ENCODING);
      }
    }
  });

  it('checks every one of the (L + K) * N s1/s2 fields', function () {
    for (let poly = 0; poly < L + K; ++poly) {
      const offset = S1_OFFSET + poly * PolyETAPackedBytes;
      for (let index = 0; index < N; ++index) {
        expect(validateSecretKey(withEtaField(sk, offset, index, 7)).ok, `poly ${poly} index ${index}`).to.equal(false);
      }
    }
  });

  it('does not examine rho, K, tr or t0', function () {
    for (const fill of [0x00, 0xff]) {
      const head = Uint8Array.from(sk).fill(fill, 0, S1_OFFSET);
      expect(validateSecretKey(head)).to.deep.equal(OK);
      const tail = Uint8Array.from(sk).fill(fill, T0_OFFSET);
      expect(validateSecretKey(tail)).to.deep.equal(OK);
    }
  });

  it('does not modify its input', function () {
    const before = Uint8Array.from(sk);
    validateSecretKey(sk);
    expect(sk).to.deep.equal(before);
    const invalid = withEtaField(sk, S1_OFFSET, 0, 7);
    const invalidBefore = Uint8Array.from(invalid);
    validateSecretKey(invalid);
    expect(invalid).to.deep.equal(invalidBefore);
  });

  it('control: the generated key still signs and verifies', function () {
    const sig = new Uint8Array(CryptoBytes);
    expect(cryptoSignSignatureDeterministic(sig, MESSAGE, sk, CTX)).to.equal(0);
    expect(cryptoSignVerify(sig, MESSAGE, pk, CTX)).to.equal(true);
  });
});

describe('signing with an invalid secret key', function () {
  const { sk } = keypair(0x07);
  const invalid = withEtaField(sk, S2_OFFSET + 3 * PolyETAPackedBytes, 17, 5);

  it('every signing entry point throws invalid-sk-encoding before writing a signature', function () {
    const sig = new Uint8Array(CryptoBytes);
    expect(() => cryptoSignSignature(sig, MESSAGE, invalid, true, CTX)).to.throw(/invalid-sk-encoding/);
    expect(() => cryptoSignSignature(sig, MESSAGE, invalid, false, CTX)).to.throw(/invalid-sk-encoding/);
    expect(() => cryptoSignSignatureDeterministic(sig, MESSAGE, invalid, CTX)).to.throw(/invalid-sk-encoding/);
    expect(() => cryptoSign(MESSAGE, invalid, true, CTX)).to.throw(/invalid-sk-encoding/);
    expect(() => cryptoSignDeterministic(MESSAGE, invalid, CTX)).to.throw(/invalid-sk-encoding/);
    expect(sig.every((b) => b === 0)).to.equal(true);
  });

  it('the thrown key is the one validateSecretKey rejects', function () {
    expect(validateSecretKey(invalid)).to.deep.equal(BAD_ENCODING);
  });
});

describe('t0 and the attempt bound', function () {
  // t0 has no invalid encoding, so validateSecretKey does not look at it,
  // and it is the one field a caller can shape to slow signing down: with
  // every coefficient at full magnitude (4096 or -4095, signs from a fixed
  // xorshift32 stream) c*t0 has a root-mean-square coefficient of about
  // sqrt(TAU)*4096 = 31700 and each attempt needs about 100 hints against
  // the OMEGA = 75 a signature can carry, so roughly 99 attempts in 100 are
  // rejected on the hint count (a generated key is accepted about once in
  // four). The loop still ends: here on attempt 36, and in any case within
  // the 1024-attempt bound.
  this.timeout(120000);

  function fullMagnitudeT0(sk) {
    const crafted = Uint8Array.from(sk);
    const t0 = new Poly();
    let x = 0x9e3779b9;
    for (let i = 0; i < K; ++i) {
      for (let j = 0; j < N; ++j) {
        x ^= x << 13;
        x ^= x >>> 17;
        x ^= x << 5;
        x >>>= 0;
        t0.coeffs[j] = x & 1 ? 4096 : -4095;
      }
      polyT0Pack(crafted, T0_OFFSET + i * PolyT0PackedBytes, t0);
    }
    return crafted;
  }

  it('a full-magnitude t0 passes validateSecretKey and signing still completes', function () {
    const { pk, sk } = keypair(0x13);
    const crafted = fullMagnitudeT0(sk);
    expect(validateSecretKey(crafted)).to.deep.equal(OK);
    const sig = new Uint8Array(CryptoBytes);
    expect(cryptoSignSignatureDeterministic(sig, MESSAGE, crafted, CTX)).to.equal(0);
    // The hints were computed from the wrong t0, so the signature does not
    // verify under the honest public key.
    expect(cryptoSignVerify(sig, MESSAGE, pk, CTX)).to.equal(false);
  });
});
