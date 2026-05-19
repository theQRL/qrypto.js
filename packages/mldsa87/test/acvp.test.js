// NIST ACVP test-vector consistency for ML-DSA-87.
//
// Mirrors the go-qrllib / rust-qrllib ACVP integration: clones the
// official NIST ACVP-Server at CI time, joins the keyGen and sigGen
// prompt + expectedResults JSON files filtered to ML-DSA-87, and runs
// the resulting vectors through cryptoSignKeypair / cryptoSignSignature
// to assert byte-exact match against NIST's expected outputs.
//
// Vectors are never vendored — they always come directly from
// `https://github.com/usnistgov/ACVP-Server`. The workflow lives at
// `.github/workflows/acvp.yml`; when `ACVP_VECTORS_DIR` is not set the
// test logs a skip notice and exits successfully so day-to-day
// `npm test` doesn't require the vectors to be present.

import { expect } from 'chai';
import fs from 'node:fs';
import path from 'node:path';

import {
  CryptoBytes,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  SeedBytes,
} from '../src/const.js';
import { cryptoSignKeypair, cryptoSignSignature } from '../src/sign.js';

// Helper: decode hex into a Uint8Array.
function hex(s) {
  if (!s) return new Uint8Array(0);
  return Uint8Array.from(Buffer.from(s, 'hex'));
}

// Helper: build a map of tcId → expected from an `expectedResults.json` group.
function indexExpected(expectedJson) {
  const out = new Map();
  for (const group of expectedJson.testGroups || []) {
    for (const tc of group.tests || []) {
      out.set(tc.tcId, tc);
    }
  }
  return out;
}

describe('ACVP - ML-DSA-87', function describeAcvp() {
  const vectorsDir = process.env.ACVP_VECTORS_DIR;
  if (!vectorsDir) {
    it.skip('ACVP_VECTORS_DIR not set; skipping ACVP test', () => {});
    return;
  }

  // Allow longer timeouts; vector counts can be in the dozens and each
  // sigGen call is a full ML-DSA-87 sign.
  this.timeout(120_000);

  const keygenPath = path.join(vectorsDir, 'ML-DSA-keyGen-FIPS204');
  const siggenPath = path.join(vectorsDir, 'ML-DSA-sigGen-FIPS204');

  describe('keyGen', () => {
    const promptFile = path.join(keygenPath, 'prompt.json');
    const expectedFile = path.join(keygenPath, 'expectedResults.json');

    if (!fs.existsSync(promptFile) || !fs.existsSync(expectedFile)) {
      it.skip(`missing ${promptFile} / ${expectedFile}`, () => {});
      return;
    }

    const prompt = JSON.parse(fs.readFileSync(promptFile, 'utf8'));
    const expected = JSON.parse(fs.readFileSync(expectedFile, 'utf8'));
    const expectedById = indexExpected(expected);

    for (const group of prompt.testGroups || []) {
      if (group.parameterSet !== 'ML-DSA-87') continue;
      for (const tc of group.tests || []) {
        const exp = expectedById.get(tc.tcId);
        if (!exp) continue;
        it(`tc${tc.tcId} keypair matches NIST expected`, () => {
          const seed = hex(tc.seed);
          expect(seed.length).to.equal(SeedBytes);
          const pk = new Uint8Array(CryptoPublicKeyBytes);
          const sk = new Uint8Array(CryptoSecretKeyBytes);
          cryptoSignKeypair(seed, pk, sk);
          expect(Buffer.from(pk).toString('hex')).to.equal(exp.pk);
          expect(Buffer.from(sk).toString('hex')).to.equal(exp.sk);
        });
      }
    }
  });

  describe('sigGen', () => {
    const promptFile = path.join(siggenPath, 'prompt.json');
    const expectedFile = path.join(siggenPath, 'expectedResults.json');

    if (!fs.existsSync(promptFile) || !fs.existsSync(expectedFile)) {
      it.skip(`missing ${promptFile} / ${expectedFile}`, () => {});
      return;
    }

    const prompt = JSON.parse(fs.readFileSync(promptFile, 'utf8'));
    const expected = JSON.parse(fs.readFileSync(expectedFile, 'utf8'));
    const expectedById = indexExpected(expected);

    for (const group of prompt.testGroups || []) {
      if (group.parameterSet !== 'ML-DSA-87') continue;
      // Only test deterministic, external-interface, pure (non-preHash)
      // vectors — the qrypto.js public API supports that mode by
      // passing randomizedSigning=false.
      if (group.deterministic !== true) continue;
      if (group.signatureInterface && group.signatureInterface !== 'external') continue;
      if (group.preHash === true) continue;

      for (const tc of group.tests || []) {
        const exp = expectedById.get(tc.tcId);
        if (!exp) continue;
        it(`tc${tc.tcId} deterministic signature matches NIST expected`, () => {
          const sk = hex(tc.sk);
          expect(sk.length).to.equal(CryptoSecretKeyBytes);
          const msg = hex(tc.message);
          const ctx = hex(tc.context);
          const sig = new Uint8Array(CryptoBytes);
          cryptoSignSignature(sig, msg, sk, /* randomizedSigning */ false, ctx);
          expect(Buffer.from(sig).toString('hex')).to.equal(exp.signature);
        });
      }
    }
  });
});
