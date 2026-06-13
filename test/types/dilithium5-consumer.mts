// TypeScript consumer-compile test for @theqrl/dilithium5.
//
// Same purpose as mldsa87-consumer.mts: import and use the documented public
// API resolving through the package `exports` map to the shipped dist
// `.d.mts`, compiled under `tsc --noEmit --strict`. Dilithium5 (Round 3) has
// no FIPS 204 context parameter — the arities below differ from ML-DSA-87 by
// exactly that, which the typings must reflect.

import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignSignature,
  cryptoSignSignatureDeterministic,
  cryptoSignDeterministic,
  cryptoSignVerify,
  cryptoSignOpen,
  cryptoSignOpenWithReason,
  zeroize,
  isZero,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
  SeedBytes,
} from '@theqrl/dilithium5';
import type { CryptoSignOpenReason } from '@theqrl/dilithium5';

const _pkBytes: number = CryptoPublicKeyBytes;
const _skBytes: number = CryptoSecretKeyBytes;
const _sigBytes: number = CryptoBytes;
const _seedBytes: number = SeedBytes;

const pk = new Uint8Array(CryptoPublicKeyBytes);
const sk = new Uint8Array(CryptoSecretKeyBytes);

const seed: Uint8Array = cryptoSignKeypair(null, pk, sk);
cryptoSignKeypair(undefined, pk, sk);
cryptoSignKeypair(seed, pk, sk);

const msg = new Uint8Array([1, 2, 3]);

// Attached signing (Dilithium5 arity: msg, sk, randomized — no ctx).
const sm: Uint8Array = cryptoSign(msg, sk, true);
const smDet: Uint8Array = cryptoSignDeterministic(msg, sk);
const smHex: Uint8Array = cryptoSign('0xdeadbeef', sk, true);

// Detached signing into a caller buffer; returns 0 on success (no ctx).
const sig = new Uint8Array(CryptoBytes);
const rc: number = cryptoSignSignature(sig, msg, sk, true);
const rcDet: number = cryptoSignSignatureDeterministic(sig, msg, sk);

const ok: boolean = cryptoSignVerify(sig, msg, pk);

const opened: Uint8Array | undefined = cryptoSignOpen(sm, pk);
if (opened !== undefined) {
  const _len: number = opened.length;
}

const wr = cryptoSignOpenWithReason(sm, pk);
if (wr.ok) {
  const _m: Uint8Array = wr.message;
} else {
  const reason: CryptoSignOpenReason = wr.reason;
  void reason;
}

zeroize(sk);
const _zeroed: boolean = isZero(sk);

void [_pkBytes, _skBytes, _sigBytes, _seedBytes, smDet, smHex, rc, rcDet, ok, opened];
