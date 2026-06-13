// CJS consumer-compile test for @theqrl/mldsa87. A `.cts` file resolves the
// package `require` condition under nodenext, so this exercises the shipped
// `.d.cts` declaration copy (the `.mts` consumer covers `.d.mts`). Together
// they compile all four published declaration files.

import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignVerify,
  cryptoSignOpen,
  cryptoSignOpenWithReason,
  zeroize,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
} from '@theqrl/mldsa87';

const pk = new Uint8Array(CryptoPublicKeyBytes);
const sk = new Uint8Array(CryptoSecretKeyBytes);
cryptoSignKeypair(null, pk, sk);
const ctx = new Uint8Array(0);
const sm: Uint8Array = cryptoSign(new Uint8Array([1]), sk, true, ctx);
const opened: Uint8Array | undefined = cryptoSignOpen(sm, pk, ctx);
const ok: boolean = cryptoSignVerify(sm.subarray(0, 0), new Uint8Array([1]), pk, ctx);
const wr = cryptoSignOpenWithReason(sm, pk, ctx);
const msg: Uint8Array | null = wr.ok ? wr.message : null;
zeroize(sk);
void [opened, ok, msg];
