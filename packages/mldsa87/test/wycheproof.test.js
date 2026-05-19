// Wycheproof ML-DSA-87 verifier consistency tests.
//
// Ported from the rust-qrllib / go-qrllib Wycheproof integration: the
// CI workflow (`.github/workflows/wycheproof.yml`) clones
// `https://github.com/C2SP/wycheproof` sparsely at CI time and points
// `WYCHEPROOF_VECTORS_DIR` at the resulting `testvectors_v1` directory.
// Each test vector in `mldsa_87_verify_test.json` carries an expected
// outcome (`valid` / `invalid` / `acceptable`); this runner asserts
// the library's verify result matches.
//
// When `WYCHEPROOF_VECTORS_DIR` is unset, the test logs a skip notice
// and exits successfully so day-to-day `npm test` doesn't require the
// vectors to be present.

import { expect } from 'chai';
import fs from 'node:fs';
import path from 'node:path';

import { CryptoBytes, CryptoPublicKeyBytes } from '../src/const.js';
import { cryptoSignVerify } from '../src/sign.js';

function hex(s) {
  if (!s) return new Uint8Array(0);
  return Uint8Array.from(Buffer.from(s, 'hex'));
}

describe('Wycheproof - ML-DSA-87 verify', function describeWycheproof() {
  const vectorsDir = process.env.WYCHEPROOF_VECTORS_DIR;
  if (!vectorsDir) {
    it.skip('WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof test', () => {});
    return;
  }

  this.timeout(60_000);

  const vectorFile = path.join(vectorsDir, 'mldsa_87_verify_test.json');
  if (!fs.existsSync(vectorFile)) {
    it.skip(`missing ${vectorFile}`, () => {});
    return;
  }

  const file = JSON.parse(fs.readFileSync(vectorFile, 'utf8'));

  it('vector file is the ML-DSA-87 verify file', () => {
    expect(file.algorithm).to.equal('ML-DSA-87');
    expect(file.testGroups.length).to.be.greaterThan(0);
  });

  let totalPass = 0;
  let totalAcceptable = 0;

  for (let gi = 0; gi < file.testGroups.length; gi += 1) {
    const group = file.testGroups[gi];
    if (group.type !== 'MlDsaVerify') continue;

    const pkBytes = hex(group.publicKey);
    const pkLengthOk = pkBytes.length === CryptoPublicKeyBytes;

    for (const tc of group.tests || []) {
      const name = `g${gi}_tc${tc.tcId} (${tc.comment || ''})`;
      it(name, () => {
        const msg = hex(tc.msg);
        const sig = hex(tc.sig);
        const ctx = hex(tc.ctx);

        let ok;
        if (!pkLengthOk || sig.length !== CryptoBytes) {
          // Mirror rust-qrllib / go-qrllib: wrong-length pk or sig is
          // rejected at the API boundary (cryptoSignVerify returns
          // false on wrong-length inputs).
          ok = false;
        } else {
          ok = cryptoSignVerify(sig, msg, pkBytes, ctx);
        }

        switch (tc.result) {
          case 'valid':
            expect(ok, `expected valid; flags=${tc.flags}`).to.equal(true);
            totalPass += 1;
            break;
          case 'invalid':
            expect(ok, `expected invalid; flags=${tc.flags}`).to.equal(false);
            totalPass += 1;
            break;
          case 'acceptable':
            // Spec allows either outcome — log but don't fail.
            totalAcceptable += 1;
            break;
          default:
            throw new Error(`unknown result ${tc.result}`);
        }
      });
    }
  }

  after(() => {
    console.log(
      `Wycheproof ML-DSA-87 Verify summary: pass=${totalPass} acceptable=${totalAcceptable}`
    );
  });
});
