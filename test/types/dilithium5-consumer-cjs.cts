// CJS consumer-compile test for @theqrl/dilithium5 — see
// mldsa87-consumer-cjs.cts. Resolves the `require` condition → shipped
// `.d.cts`. Dilithium5 arities omit the FIPS 204 context parameter.

import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignVerify,
  cryptoSignOpen,
  cryptoSignOpenWithReason,
  zeroize,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
} from '@theqrl/dilithium5';

const pk = new Uint8Array(CryptoPublicKeyBytes);
const sk = new Uint8Array(CryptoSecretKeyBytes);
cryptoSignKeypair(null, pk, sk);
const sm: Uint8Array = cryptoSign(new Uint8Array([1]), sk, true);
const opened: Uint8Array | undefined = cryptoSignOpen(sm, pk);
const ok: boolean = cryptoSignVerify(sm.subarray(0, 0), new Uint8Array([1]), pk);
const wr = cryptoSignOpenWithReason(sm, pk);
const msg: Uint8Array | null = wr.ok ? wr.message : null;
zeroize(sk);
void [opened, ok, msg];
