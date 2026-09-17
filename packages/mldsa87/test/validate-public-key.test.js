// validatePublicKey: rejects weak ML-DSA-87 public keys, plus a conformance
// pin that cryptoSignVerify itself still ACCEPTS the signature such a key
// admits. FIPS 204 Algorithm 8 has no key-validity step and the
// C2SP/wycheproof ZeroPublicKey vectors (tcId 66 and 174) are `result:
// valid`, so the verifier is left alone and the check lives here.
//
// The rule: unpack the 2048 t1 coefficients; a coefficient v is large iff
// 96 <= v <= 415 or 608 <= v <= 927; the key is weak unless at least 76
// coefficients are large. The bounds are re-derived from the parameter set
// below, independently of src/sign.js, and the shared vector file
// test/vectors/weak_public_key_vectors.json is the one go-qrllib,
// rust-qrllib and wallet.js are tested against.

import { expect } from 'chai';
import { shake256 } from '@noble/hashes/sha3.js';

import {
  CRHBytes,
  CTILDEBytes,
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  D,
  GAMMA2,
  K,
  L,
  N,
  OMEGA,
  PolyT1PackedBytes,
  PolyW1PackedBytes,
  PolyZPackedBytes,
  Q,
  SeedBytes,
  TRBytes,
} from '../src/const.js';
import { packSig } from '../src/packing.js';
import { Poly, polyT1Pack, polyT1Unpack } from '../src/poly.js';
import { PolyVecK, PolyVecL } from '../src/polyvec.js';
import {
  cryptoSignKeypair,
  cryptoSignOpen,
  cryptoSignOpenWithReason,
  cryptoSignVerify,
  validatePublicKey,
} from '../src/sign.js';

const T1_COEFFICIENTS = K * N; // 2048
const WEAK = { ok: false, reason: 'weak-public-key' };
const BAD_TYPE = { ok: false, reason: 'invalid-pk-type' };
const BAD_LENGTH = { ok: false, reason: 'invalid-pk-length' };

// The rule's bounds, derived here from the parameter set independently of
// src/sign.js. A coefficient is large when each challenge tap moves it by
// more than 3*GAMMA2 both as 2^D*v centered mod Q and as
// (2^(D+1)*v centered mod Q)/2 (the 2^-1 family around v = 512).
const LARGE_LOW = Math.floor((3 * GAMMA2) / 2 ** D) + 1;
const LARGE_HIGH_BELOW_HALF = Math.floor((Q - 6 * GAMMA2) / 2 ** (D + 1));
const LARGE_LOW_ABOVE_HALF = Math.ceil((Q + 6 * GAMMA2) / 2 ** (D + 1));
const LARGE_HIGH = Math.ceil((Q - 3 * GAMMA2) / 2 ** D) - 1;
const MIN_LARGE = OMEGA + 1;

function isLarge(v) {
  return (v >= LARGE_LOW && v <= LARGE_HIGH_BELOW_HALF) || (v >= LARGE_LOW_ABOVE_HALF && v <= LARGE_HIGH);
}

/** The 2048 t1 coefficients of a packed key, via the package's own unpacker. */
function t1Coefficients(pk) {
  const out = [];
  const poly = new Poly();
  for (let i = 0; i < K; i++) {
    polyT1Unpack(poly, pk, SeedBytes + i * PolyT1PackedBytes);
    for (let j = 0; j < N; j++) out.push(poly.coeffs[j]);
  }
  return out;
}

/** Plain-comparison count of large coefficients: the reference for the branch-free scan in src. */
function countLarge(pk) {
  return t1Coefficients(pk).filter(isLarge).length;
}

/** rho || t1 with every rho byte = rhoByte and t1 coefficient i = coeff(i), i in [0, 2048). */
function keyFromT1(coeff, rhoByte = 0x2a) {
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  pk.fill(rhoByte, 0, SeedBytes);
  const poly = new Poly();
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < N; j++) poly.coeffs[j] = coeff(i * N + j);
    polyT1Pack(pk, SeedBytes + i * PolyT1PackedBytes, poly);
  }
  return pk;
}

/** The first `count` t1 coefficients equal to `value`, the rest zero. */
function keyWithCoefficients(count, value) {
  return keyFromT1((i) => (i < count ? value : 0));
}

/** rho || zeros(t1) with a caller-chosen rho byte. */
function zeroT1Key(rhoByte) {
  return keyFromT1(() => 0, rhoByte);
}

function generatedKey(seed) {
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  cryptoSignKeypair(seed, pk, sk);
  return pk;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/**
 * The zero-hint signature a weak key admits, built from public data only:
 *   z = 0, h = 0, c~ = SHAKE256(mu || w1Encode(0))
 *   mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg), tr = SHAKE256(pk)
 * The verifier reconstructs w1' = UseHint(0, A·0 − c·2^d·t1); when every
 * coefficient of that has HighBits 0 its recomputed c~ matches ours.
 */
function forgeSignature(pk, msg, ctx) {
  const tr = shake256.create({}).update(pk).xof(TRBytes);
  const pre = new Uint8Array(2 + ctx.length);
  pre[0] = 0;
  pre[1] = ctx.length;
  pre.set(ctx, 2);
  const mu = shake256.create({}).update(tr).update(pre).update(msg).xof(CRHBytes);
  // w1Encode(0): K zero polynomials pack to K * PolyW1PackedBytes zero bytes.
  const w1Zero = new Uint8Array(K * PolyW1PackedBytes);
  const ctilde = shake256.create({}).update(mu).update(w1Zero).xof(CTILDEBytes);

  // Pack with the library's own encoder: fresh PolyVecL / PolyVecK are
  // zero-initialised, so this is exactly (c~, z = 0, h = 0).
  const sig = new Uint8Array(CryptoBytes);
  packSig(sig, ctilde, new PolyVecL(), new PolyVecK());
  return sig;
}

const CTX = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]); // "ZOND"
const MSG = new TextEncoder().encode('any message at all');

function zeroHintForgeryVerifies(pk) {
  return cryptoSignVerify(forgeSignature(pk, MSG, CTX), MSG, pk, CTX);
}

/** Shared vector file: fs in Node, fetch in the browser runner (same origin). */
async function loadSharedVectors() {
  const url = new URL('./vectors/weak_public_key_vectors.json', import.meta.url);
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    const fs = await import('node:fs');
    return JSON.parse(fs.readFileSync(url, 'utf8'));
  }
  const response = await fetch(url);
  return response.json();
}

describe('validatePublicKey', () => {
  describe('rule bounds (derived from the parameter set)', () => {
    it('the parameter set is ML-DSA-87', () => {
      expect(Q).to.equal(8380417);
      expect(D).to.equal(13);
      expect(GAMMA2).to.equal(261888);
      expect(OMEGA).to.equal(75);
      expect(T1_COEFFICIENTS).to.equal(2048);
    });

    it('derives to the documented literals: large iff v in [96, 415] or [608, 927], minimum 76', () => {
      expect(LARGE_LOW).to.equal(96);
      expect(LARGE_HIGH_BELOW_HALF).to.equal(415);
      expect(LARGE_LOW_ABOVE_HALF).to.equal(608);
      expect(LARGE_HIGH).to.equal(927);
      expect(MIN_LARGE).to.equal(76);
    });

    it('76 copies of v are accepted exactly when v is large, for every v in [0, 1023]', () => {
      for (let v = 0; v < 1024; v++) {
        const pk = keyWithCoefficients(MIN_LARGE, v);
        expect(countLarge(pk), `count for v = ${v}`).to.equal(isLarge(v) ? MIN_LARGE : 0);
        expect(validatePublicKey(pk), `v = ${v}`).to.deep.equal(isLarge(v) ? { ok: true } : WEAK);
      }
    });

    it('band edges: 96, 415, 608, 927 count; 95, 416, 607, 928 do not', () => {
      for (const v of [96, 415, 608, 927]) {
        expect(validatePublicKey(keyWithCoefficients(MIN_LARGE, v)), `v = ${v}`).to.deep.equal({ ok: true });
      }
      for (const v of [95, 416, 607, 928]) {
        expect(validatePublicKey(keyWithCoefficients(MIN_LARGE, v)), `v = ${v}`).to.deep.equal(WEAK);
      }
    });

    it('75 large coefficients are weak, 76 are accepted', () => {
      expect(validatePublicKey(keyWithCoefficients(MIN_LARGE - 1, 300))).to.deep.equal(WEAK);
      expect(validatePublicKey(keyWithCoefficients(MIN_LARGE, 300))).to.deep.equal({ ok: true });
    });

    it('counts across all K polynomials and across both bands', () => {
      // One large coefficient every 27th position: 76 of them span every polynomial.
      const spread = keyFromT1((i) => (i % 27 === 0 && i / 27 < MIN_LARGE ? 200 : 0));
      expect(countLarge(spread)).to.equal(MIN_LARGE);
      expect(validatePublicKey(spread)).to.deep.equal({ ok: true });

      // 38 in the lower band and 38 in the upper band.
      const mixed = keyFromT1((i) => {
        if (i < 38) return 100;
        if (i < MIN_LARGE) return 900;
        return 0;
      });
      expect(countLarge(mixed)).to.equal(MIN_LARGE);
      expect(validatePublicKey(mixed)).to.deep.equal({ ok: true });
    });

    it('near misses never count, however many there are', () => {
      // 75 large coefficients plus 1973 coefficients just outside the bands.
      const nearMiss = [95, 416, 607, 928];
      const pk = keyFromT1((i) => (i < MIN_LARGE - 1 ? 300 : nearMiss[i % 4]));
      expect(countLarge(pk)).to.equal(MIN_LARGE - 1);
      expect(validatePublicKey(pk)).to.deep.equal(WEAK);
    });
  });

  describe('weak-public-key', () => {
    it('rejects the all-zero public key', () => {
      expect(validatePublicKey(new Uint8Array(CryptoPublicKeyBytes))).to.deep.equal(WEAK);
    });

    it('rejects rho = 0xab.. with zero t1', () => {
      expect(validatePublicKey(zeroT1Key(0xab))).to.deep.equal(WEAK);
    });

    it('rejects the Wycheproof ZeroPublicKey rho values (0x2a.. tcId 66, 0x2b.. tcId 174)', () => {
      expect(validatePublicKey(zeroT1Key(0x2a))).to.deep.equal(WEAK);
      expect(validatePublicKey(zeroT1Key(0x2b))).to.deep.equal(WEAK);
    });

    it('excludes rho: a non-zero byte at every rho byte position individually is still weak', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes);
      for (let i = 0; i < SeedBytes; i++) {
        pk[i] = 0xff;
        expect(validatePublicKey(pk), `rho byte ${i}`).to.deep.equal(WEAK);
        pk[i] = 0;
      }
    });

    it('rejects a Node Buffer (Uint8Array subclass) with zero t1', () => {
      expect(validatePublicKey(Buffer.alloc(CryptoPublicKeyBytes))).to.deep.equal(WEAK);
    });

    it('rejects a single non-zero t1 byte at every position: one or two coefficients are never enough', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes);
      for (let pos = SeedBytes; pos < CryptoPublicKeyBytes; pos++) {
        pk[pos] = 0xff;
        expect(validatePublicKey(pk), `t1 byte at ${pos}`).to.deep.equal(WEAK);
        pk[pos] = 0;
      }
    });

    it('rejects every coefficient 1023 (all t1 bytes 0xff): 2^13 * 1023 = q - 1', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes).fill(0xff);
      expect(countLarge(pk)).to.equal(0);
      expect(validatePublicKey(pk)).to.deep.equal(WEAK);
    });

    it('rejects every coefficient 512 (the 2^-1 family)', () => {
      const pk = keyFromT1(() => 512);
      expect(countLarge(pk)).to.equal(0);
      expect(validatePublicKey(pk)).to.deep.equal(WEAK);
    });
  });

  describe('ok', () => {
    it('accepts a freshly generated key (random seed)', () => {
      expect(validatePublicKey(generatedKey(null))).to.deep.equal({ ok: true });
    });

    it('accepts a key generated from a fixed seed', () => {
      expect(validatePublicKey(generatedKey(new Uint8Array(SeedBytes)))).to.deep.equal({ ok: true });
    });

    it('generated keys have far more large coefficients than the minimum', () => {
      // The expected fraction is 0.625 of 2048, about 1280; the lowest seen
      // over 500 keys was 1230. Fixed seeds keep this deterministic.
      for (let s = 0; s < 8; s++) {
        const pk = generatedKey(new Uint8Array(SeedBytes).fill(s));
        const count = countLarge(pk);
        expect(count > 1100, `seed ${s}: ${count} large coefficients`).to.equal(true);
        expect(validatePublicKey(pk), `seed ${s}`).to.deep.equal({ ok: true });
      }
    });

    it('accepts a Node Buffer (Uint8Array subclass) holding a generated key', () => {
      expect(validatePublicKey(Buffer.from(generatedKey(new Uint8Array(SeedBytes))))).to.deep.equal({ ok: true });
    });

    it('scans only the view when pk is a subarray of a larger buffer', () => {
      // Bytes outside the view must neither rescue a zero-t1 view nor sink a
      // good one, and the key inside the view is read relative to the view.
      const backing = new Uint8Array(CryptoPublicKeyBytes + 64).fill(0xff);
      const view = backing.subarray(32, 32 + CryptoPublicKeyBytes);
      view.fill(0);
      expect(validatePublicKey(view)).to.deep.equal(WEAK);
      view.set(generatedKey(new Uint8Array(SeedBytes)));
      expect(validatePublicKey(view)).to.deep.equal({ ok: true });
      backing.fill(0, 0, 32);
      backing.fill(0, 32 + CryptoPublicKeyBytes);
      expect(validatePublicKey(view)).to.deep.equal({ ok: true });
    });
  });

  describe('invalid-pk-length', () => {
    for (const len of [0, 1, SeedBytes, CryptoPublicKeyBytes - 1, CryptoPublicKeyBytes + 1]) {
      it(`rejects a ${len}-byte Uint8Array`, () => {
        expect(validatePublicKey(new Uint8Array(len))).to.deep.equal(BAD_LENGTH);
      });
    }

    it('reports a Uint8Array over a detached ArrayBuffer as a length error, without throwing', () => {
      const pk = generatedKey(new Uint8Array(SeedBytes));
      structuredClone(pk.buffer, { transfer: [pk.buffer] }); // detaches pk.buffer
      expect(pk.length).to.equal(0);
      expect(validatePublicKey(pk)).to.deep.equal(BAD_LENGTH);
    });
  });

  describe('invalid-pk-type', () => {
    const cases = [
      ['null', null],
      ['undefined', undefined],
      ['hex string', '00'.repeat(CryptoPublicKeyBytes)],
      ['plain Array', new Array(CryptoPublicKeyBytes).fill(0)],
      ['ArrayBuffer', new ArrayBuffer(CryptoPublicKeyBytes)],
      ['Int8Array', new Int8Array(CryptoPublicKeyBytes)],
      ['Uint16Array', new Uint16Array(CryptoPublicKeyBytes)],
      ['Uint8ClampedArray', new Uint8ClampedArray(CryptoPublicKeyBytes)],
      ['DataView', new DataView(new ArrayBuffer(CryptoPublicKeyBytes))],
      ['number', CryptoPublicKeyBytes],
      ['boolean', true],
      ['array-like object', { length: CryptoPublicKeyBytes }],
      ['function', () => {}],
      ['bigint', 0n],
      ['symbol', Symbol('pk')],
    ];
    for (const [label, value] of cases) {
      it(`rejects ${label}`, () => {
        expect(validatePublicKey(value)).to.deep.equal(BAD_TYPE);
      });
    }
  });

  it('never throws, for any input', () => {
    const inputs = [
      null,
      undefined,
      0,
      '',
      {},
      [],
      new Uint8Array(0),
      new Uint8Array(CryptoPublicKeyBytes),
      new ArrayBuffer(0),
      Buffer.alloc(CryptoPublicKeyBytes),
    ];
    for (const value of inputs) {
      expect(() => validatePublicKey(value)).to.not.throw();
    }
  });
});

describe('validatePublicKey - shared weak-key vectors (test/vectors/weak_public_key_vectors.json)', () => {
  // The same file is checked into go-qrllib, rust-qrllib and wallet.js; every
  // client applies the same rule to it.
  let file;
  before(async () => {
    file = await loadSharedVectors();
  });

  it('is the ML-DSA-87 vector file: 28 vectors, 2048 coefficients, bounds equal to the derived literals', () => {
    expect(file.parameterSet).to.equal('ML-DSA-87');
    expect(file.t1Coefficients).to.equal(T1_COEFFICIENTS);
    expect(file.largeLow).to.equal(LARGE_LOW);
    expect(file.largeHighBelowHalf).to.equal(LARGE_HIGH_BELOW_HALF);
    expect(file.largeLowAboveHalf).to.equal(LARGE_LOW_ABOVE_HALF);
    expect(file.largeHigh).to.equal(LARGE_HIGH);
    expect(file.minLargeCoefficients).to.equal(MIN_LARGE);
    expect(file.description).to.be.a('string');
    expect(file.vectors.length).to.equal(28);
    for (const v of file.vectors) {
      expect(v.pk.length, v.name).to.equal(2 * CryptoPublicKeyBytes);
      expect(v.expected === 'accept' || v.expected === 'weak', `${v.name}: expected = ${v.expected}`).to.equal(true);
      expect(typeof v.zeroHintForgeryVerifies, v.name).to.equal('boolean');
    }
  });

  it('(a) validatePublicKey accepts every "accept" vector and rejects every "weak" vector as weak-public-key', () => {
    for (const v of file.vectors) {
      const expected = v.expected === 'accept' ? { ok: true } : WEAK;
      expect(validatePublicKey(hexToBytes(v.pk)), v.name).to.deep.equal(expected);
    }
  });

  it('(b) the large-coefficient count equals largeCoefficients and decides the verdict', () => {
    for (const v of file.vectors) {
      const count = countLarge(hexToBytes(v.pk));
      expect(count, v.name).to.equal(v.largeCoefficients);
      expect(count >= MIN_LARGE, `${v.name}: ${count} large`).to.equal(v.expected === 'accept');
    }
  });

  it('(c) cryptoSignVerify accepts the zero-hint signature under every key marked zeroHintForgeryVerifies', () => {
    let checked = 0;
    const emptyCtx = new Uint8Array(0);
    for (const v of file.vectors) {
      if (!v.zeroHintForgeryVerifies) continue;
      const pk = hexToBytes(v.pk);
      expect(v.expected, v.name).to.equal('weak');
      expect(zeroHintForgeryVerifies(pk), v.name).to.equal(true);
      const other = new TextEncoder().encode(`another message for ${v.name}`);
      expect(cryptoSignVerify(forgeSignature(pk, other, emptyCtx), other, pk, emptyCtx), v.name).to.equal(true);
      checked++;
    }
    expect(checked > 0).to.equal(true);
  });

  it('(d) the zero-hint signature does not verify under any "accept" vector', () => {
    let checked = 0;
    for (const v of file.vectors) {
      if (v.expected !== 'accept') continue;
      expect(zeroHintForgeryVerifies(hexToBytes(v.pk)), v.name).to.equal(false);
      checked++;
    }
    expect(checked > 0).to.equal(true);
  });
});

describe('FIPS 204 conformance pin: cryptoSignVerify accepts the zero-hint signature under the all-zero-t1 key', () => {
  // Algorithm 8 (ML-DSA.Verify) has no key-validity precondition. The
  // Wycheproof ZeroPublicKey vectors tcId 66 and 174 are `result: valid` and
  // test/wycheproof.test.js requires cryptoSignVerify to accept them, so this
  // block pins that the verifier is NOT changed: the rejection lives in
  // validatePublicKey, which callers run on keys they receive.
  const pk = zeroT1Key(0x2a); // rho as in Wycheproof tcId 66
  const sig = forgeSignature(pk, MSG, CTX);

  it('the signature has the documented byte layout (c~ || z = 0 || h = 0)', () => {
    expect(sig.length).to.equal(CryptoBytes);
    expect(CTILDEBytes + L * PolyZPackedBytes + OMEGA + K).to.equal(CryptoBytes);

    // z = 0: each coefficient encodes GAMMA1 - 0 = 2^19; two coefficients per
    // five bytes give the repeating group [0x00, 0x00, 0x08, 0x00, 0x80].
    const zStart = CTILDEBytes;
    const zEnd = zStart + L * PolyZPackedBytes;
    const expectedZ = new Uint8Array(L * PolyZPackedBytes);
    const group = [0x00, 0x00, 0x08, 0x00, 0x80];
    for (let i = 0; i < expectedZ.length; i++) expectedZ[i] = group[i % 5];
    expect(Array.from(sig.subarray(zStart, zEnd))).to.deep.equal(Array.from(expectedZ));

    // h = 0: OMEGA + K zero bytes (no hint indices, all K counters zero).
    expect(Array.from(sig.subarray(zEnd))).to.deep.equal(new Array(OMEGA + K).fill(0));
  });

  it('cryptoSignVerify ACCEPTS it: FIPS 204 behaviour, not something to fix in the verifier', () => {
    expect(cryptoSignVerify(sig, MSG, pk, CTX)).to.equal(true);
  });

  it('holds for any message, context and rho with a recomputed c~', () => {
    const otherMsg = new TextEncoder().encode('a completely different message');
    const emptyCtx = new Uint8Array(0);
    expect(cryptoSignVerify(forgeSignature(pk, otherMsg, CTX), otherMsg, pk, CTX)).to.equal(true);
    expect(cryptoSignVerify(forgeSignature(pk, otherMsg, emptyCtx), otherMsg, pk, emptyCtx)).to.equal(true);
    expect(cryptoSignVerify(forgeSignature(pk, new Uint8Array(0), CTX), new Uint8Array(0), pk, CTX)).to.equal(true);

    const pk2 = zeroT1Key(0x2b); // rho as in Wycheproof tcId 174
    expect(cryptoSignVerify(forgeSignature(pk2, MSG, CTX), MSG, pk2, CTX)).to.equal(true);
  });

  it('cryptoSignOpen and cryptoSignOpenWithReason accept it too', () => {
    const sm = new Uint8Array(CryptoBytes + MSG.length);
    sm.set(sig);
    sm.set(MSG, CryptoBytes);
    expect(Array.from(cryptoSignOpen(sm, pk, CTX))).to.deep.equal(Array.from(MSG));
    expect(cryptoSignOpenWithReason(sm, pk, CTX).ok).to.equal(true);
  });

  it('validatePublicKey rejects the same key', () => {
    expect(validatePublicKey(pk)).to.deep.equal(WEAK);
  });

  it('negative control: a generated key passes validation and the signature fails under it', () => {
    const honestPk = generatedKey(new Uint8Array(SeedBytes));
    expect(validatePublicKey(honestPk)).to.deep.equal({ ok: true });
    expect(zeroHintForgeryVerifies(honestPk)).to.equal(false);
  });
});

// Cross-check against the pinned C2SP/wycheproof vectors when they are
// present (same env-var gate as test/wycheproof.test.js, skipped otherwise and
// in the browser). Wycheproof carries two crafted keys: the `ZeroPublicKey`
// groups (t1 = 0, tcId 66 and 174) and the `MissingReduction` group (t1 = all
// 1023, tcId 240 and 241; 2^13 * 1023 = q - 1, the "every coefficient 1023"
// vector in test/vectors/weak_public_key_vectors.json). Both are weak, the
// zero-hint signature verifies under both, and both must be rejected here;
// every other group's key is a generated key and must be accepted.
describe('validatePublicKey - Wycheproof cross-check', () => {
  const vectorsDir = typeof process === 'undefined' ? undefined : process.env.WYCHEPROOF_VECTORS_DIR;
  if (!vectorsDir) {
    it.skip('WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof cross-check', () => {});
    return;
  }

  it('rejects exactly the ZeroPublicKey and MissingReduction keys and accepts every generated key', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const file = JSON.parse(fs.readFileSync(path.join(vectorsDir, 'mldsa_87_verify_test.json'), 'utf8'));
    expect(file.algorithm).to.equal('ML-DSA-87');

    const weakTcIds = [];
    let accepted = 0;
    for (const group of file.testGroups) {
      const pk = Uint8Array.from(Buffer.from(group.publicKey, 'hex'));
      const tcIds = group.tests.map((tc) => tc.tcId);
      const flags = new Set(group.tests.flatMap((tc) => tc.flags));
      const result = validatePublicKey(pk);
      if (pk.length !== CryptoPublicKeyBytes) {
        expect(result, `tcIds ${tcIds}`).to.deep.equal(BAD_LENGTH);
      } else if (flags.has('ZeroPublicKey') || flags.has('MissingReduction')) {
        expect(result, `tcIds ${tcIds}`).to.deep.equal(WEAK);
        expect(countLarge(pk), `tcIds ${tcIds}`).to.equal(0);
        expect(zeroHintForgeryVerifies(pk), `tcIds ${tcIds}`).to.equal(true);
        weakTcIds.push(...tcIds);
      } else {
        expect(result, `tcIds ${tcIds}`).to.deep.equal({ ok: true });
        accepted += 1;
      }
    }
    expect(weakTcIds).to.include.members([66, 174, 240, 241]);
    expect(accepted).to.be.greaterThan(0);
  });
});
