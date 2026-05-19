// Metamorphic property tests for ML-DSA-87.
//
// Port of the ToB-handoff metamorphic-fuzz patterns delivered during
// the `go-qrllib` Trail of Bits engagement (`crypto/ml_dsa_87/
// metamorphic_fuzz_test.go`). Adapted to deterministic seeded mocha
// tests so they run on every `npm test` rather than requiring a fuzz
// driver. Each property:
//
//  1. Verify rejects a single-bit-mauled public key.
//  2. Verify rejects a single-bit-mauled message.
//  3. Verify rejects a single-bit-mauled signature.
//  4. Deterministic signing yields distinct bytes on a mauled message.
//  5. Open rejects a single-bit-mauled attached signature.
//
// The properties run against a hand-curated 3-seed × 3-input corpus.
// Each iteration is fast enough that the whole file completes well
// under the existing 1s test budget per spec file. (TOB-QRLLIB
// cross-cutting: ToB-handoff metamorphic fuzzer port.)

import { expect } from 'chai';
import { CryptoBytes, CryptoPublicKeyBytes, CryptoSecretKeyBytes, SeedBytes } from '../src/const.js';
import {
  cryptoSign,
  cryptoSignKeypair,
  cryptoSignOpen,
  cryptoSignSignature,
  cryptoSignSignatureDeterministic,
  cryptoSignVerify,
} from '../src/sign.js';

function makeSeed(byte) {
  const seed = new Uint8Array(SeedBytes);
  for (let i = 0; i < SeedBytes; i += 1) seed[i] = (byte + i) & 0xff;
  return seed;
}

function corpusSeeds() {
  return [makeSeed(0x00), makeSeed(0xff), makeSeed(0x42)];
}

function corpusInputs() {
  return [
    { ctx: new Uint8Array(0), msg: new TextEncoder().encode('') },
    { ctx: new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]), msg: new TextEncoder().encode('Hello') },
    { ctx: new Uint8Array(255).fill(0x41), msg: new TextEncoder().encode('M'.repeat(64)) },
  ];
}

function flipSingleBit(src, bitIndex) {
  const out = new Uint8Array(src);
  const bit = bitIndex % (out.length * 8);
  out[bit >> 3] ^= 1 << (bit & 7);
  return out;
}

function keypairFromSeed(seed) {
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  cryptoSignKeypair(seed, pk, sk);
  return { pk, sk };
}

function detSign(sk, msg, ctx) {
  const sig = new Uint8Array(CryptoBytes);
  cryptoSignSignatureDeterministic(sig, msg, sk, ctx);
  return sig;
}

describe('metamorphic: verify rejects mauled public key (TOB-QRLLIB-handoff)', () => {
  for (const seed of corpusSeeds()) {
    for (const { ctx, msg } of corpusInputs()) {
      it(`seed=${seed[0].toString(16)} ctx_len=${ctx.length} msg_len=${msg.length}`, () => {
        const { pk, sk } = keypairFromSeed(seed);
        const sig = detSign(sk, msg, ctx);
        expect(cryptoSignVerify(sig, msg, pk, ctx)).to.equal(true);

        // Try a few different bit indices spread across the pk.
        for (const bit of [0, 7, 100, CryptoPublicKeyBytes * 4, CryptoPublicKeyBytes * 8 - 1]) {
          const mauledPk = flipSingleBit(pk, bit);
          expect(cryptoSignVerify(sig, msg, mauledPk, ctx), `single-bit mauled pk verified at bit ${bit}`).to.equal(
            false
          );
        }
      });
    }
  }
});

describe('metamorphic: verify rejects mauled message', () => {
  for (const seed of corpusSeeds()) {
    for (const { ctx, msg } of corpusInputs()) {
      if (msg.length === 0) continue; // can't bit-flip an empty msg meaningfully
      it(`seed=${seed[0].toString(16)} ctx_len=${ctx.length} msg_len=${msg.length}`, () => {
        const { pk, sk } = keypairFromSeed(seed);
        const sig = detSign(sk, msg, ctx);
        expect(cryptoSignVerify(sig, msg, pk, ctx)).to.equal(true);

        for (let bit = 0; bit < Math.min(64, msg.length * 8); bit += 11) {
          const mauledMsg = flipSingleBit(msg, bit);
          expect(
            cryptoSignVerify(sig, mauledMsg, pk, ctx),
            `single-bit mauled message verified at bit ${bit}`
          ).to.equal(false);
        }
      });
    }
  }
});

describe('metamorphic: verify rejects mauled signature', () => {
  for (const seed of corpusSeeds()) {
    for (const { ctx, msg } of corpusInputs()) {
      it(`seed=${seed[0].toString(16)} ctx_len=${ctx.length} msg_len=${msg.length}`, () => {
        const { pk, sk } = keypairFromSeed(seed);
        const sig = detSign(sk, msg, ctx);
        expect(cryptoSignVerify(sig, msg, pk, ctx)).to.equal(true);

        for (const bit of [0, 1, 127, CryptoBytes * 4, CryptoBytes * 8 - 1]) {
          const mauledSig = flipSingleBit(sig, bit);
          expect(
            cryptoSignVerify(mauledSig, msg, pk, ctx),
            `single-bit mauled signature verified at bit ${bit}`
          ).to.equal(false);
        }
      });
    }
  }
});

describe('metamorphic: deterministic signing differs on mauled message (TOB-QRLLIB-6 mode)', () => {
  for (const seed of corpusSeeds()) {
    for (const { ctx, msg } of corpusInputs()) {
      if (msg.length === 0) continue;
      it(`seed=${seed[0].toString(16)} ctx_len=${ctx.length} msg_len=${msg.length}`, () => {
        const { sk } = keypairFromSeed(seed);
        const base = detSign(sk, msg, ctx);
        for (let bit = 0; bit < Math.min(64, msg.length * 8); bit += 11) {
          const mauledMsg = flipSingleBit(msg, bit);
          const mauledSig = detSign(sk, mauledMsg, ctx);
          expect(
            Buffer.from(base).equals(Buffer.from(mauledSig)),
            `deterministic signing collision on mauled message at bit ${bit}`
          ).to.equal(false);
        }
      });
    }
  }
});

describe('metamorphic: open rejects mauled attached signature', () => {
  for (const seed of corpusSeeds()) {
    for (const { ctx, msg } of corpusInputs()) {
      it(`seed=${seed[0].toString(16)} ctx_len=${ctx.length} msg_len=${msg.length}`, () => {
        const { pk, sk } = keypairFromSeed(seed);
        // sign attached, hedged (matches TOB-QRLLIB-6 recommended default)
        const sealed = cryptoSign(msg, sk, /* randomizedSigning */ true, ctx);
        const opened = cryptoSignOpen(sealed, pk, ctx);
        expect(opened).to.not.equal(undefined);
        expect(Buffer.from(opened).equals(Buffer.from(msg))).to.equal(true);

        // Maul only the signature prefix (mirrors go-qrllib's port:
        // the message-suffix portion of `sealed` is plain bytes and
        // mauling it would just give Open a different recovered msg).
        for (const bit of [0, 7, 1000, CryptoBytes * 8 - 1]) {
          const mauledPrefix = flipSingleBit(sealed.subarray(0, CryptoBytes), bit);
          const mauledSealed = new Uint8Array(sealed.length);
          mauledSealed.set(mauledPrefix);
          mauledSealed.set(sealed.subarray(CryptoBytes), CryptoBytes);
          expect(
            cryptoSignOpen(mauledSealed, pk, ctx),
            `single-bit mauled attached signature opened at bit ${bit}`
          ).to.equal(undefined);
        }
      });
    }
  }
});

// Silence unused-import lint: cryptoSignSignature is referenced via
// the deterministic-mode helper indirectly. Keep imported for
// discoverability when expanding the corpus.
void cryptoSignSignature;
