// TypeScript consumer-compile test for @theqrl/mldsa87.
//
// Imports and uses every symbol in the documented public API (README "API
// Reference") as a downstream consumer would, resolving through the package
// `exports` map to the shipped dist `.d.mts`. Compiled with
// `tsc --noEmit --strict` via test/types/tsconfig.json. Any signature drift,
// missing export, or lost union/overload information surfaces as a compile
// error before it ships to npm.

import {
  cryptoSignKeypair,
  cryptoSign,
  cryptoSignSignature,
  cryptoSignSignatureDeterministic,
  cryptoSignDeterministic,
  cryptoSignVerify,
  cryptoSignOpen,
  cryptoSignOpenWithReason,
  validatePublicKey,
  validateSecretKey,
  zeroize,
  isZero,
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
  SeedBytes,
} from '@theqrl/mldsa87';
import type { CryptoSignOpenReason, ValidatePublicKeyReason, ValidateSecretKeyReason } from '@theqrl/mldsa87';

// Byte-size constants are typed `number`.
const _pkBytes: number = CryptoPublicKeyBytes;
const _skBytes: number = CryptoSecretKeyBytes;
const _sigBytes: number = CryptoBytes;
const _seedBytes: number = SeedBytes;

const pk = new Uint8Array(CryptoPublicKeyBytes);
const sk = new Uint8Array(CryptoSecretKeyBytes);

// Keygen returns the (secret-key-equivalent) seed; null/undefined allowed.
const seed: Uint8Array = cryptoSignKeypair(null, pk, sk);
cryptoSignKeypair(undefined, pk, sk);
cryptoSignKeypair(seed, pk, sk);

const msg = new Uint8Array([1, 2, 3]);
const ctx = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]); // "ZOND"

// Attached signing (ML-DSA-87 arity: msg, sk, randomized, ctx).
const sm: Uint8Array = cryptoSign(msg, sk, true, ctx);
const smDet: Uint8Array = cryptoSignDeterministic(msg, sk, ctx);
// String (hex) messages are accepted by the documented signature.
const smHex: Uint8Array = cryptoSign('0xdeadbeef', sk, true, ctx);

// Detached signing into a caller buffer; returns 0 on success.
const sig = new Uint8Array(CryptoBytes);
const rc: number = cryptoSignSignature(sig, msg, sk, true, ctx);
const rcDet: number = cryptoSignSignatureDeterministic(sig, msg, sk, ctx);

// Verify is total → boolean.
const ok: boolean = cryptoSignVerify(sig, msg, pk, ctx);

// Open is total → Uint8Array | undefined.
const opened: Uint8Array | undefined = cryptoSignOpen(sm, pk, ctx);
if (opened !== undefined) {
  const _len: number = opened.length;
}

// WithReason: discriminated-union narrowing must type-check both arms.
const wr = cryptoSignOpenWithReason(sm, pk, ctx);
if (wr.ok) {
  const _m: Uint8Array = wr.message;
} else {
  const reason: CryptoSignOpenReason = wr.reason;
  // Every documented reason literal must be assignable.
  const _reasons: CryptoSignOpenReason[] = [
    'invalid-ctx-type',
    'invalid-ctx-length',
    'invalid-sm-type',
    'invalid-sm-length',
    'invalid-pk',
    'verification-failed',
  ];
  void reason;
  void _reasons;
}

// validatePublicKey: takes `unknown` (never throws), returns a discriminated
// union whose ok-arm carries no `reason`.
const vpk = validatePublicKey(pk);
if (vpk.ok) {
  const _isOk: true = vpk.ok;
  // @ts-expect-error — the ok arm has no `reason` property.
  const _noReason: unknown = vpk.reason;
  void [_isOk, _noReason];
} else {
  const vreason: ValidatePublicKeyReason = vpk.reason;
  const _vreasons: ValidatePublicKeyReason[] = ['invalid-pk-type', 'invalid-pk-length', 'weak-public-key'];
  void [vreason, _vreasons];
}
validatePublicKey(null);
validatePublicKey(undefined);
validatePublicKey('not a key');
validatePublicKey([1, 2, 3]);

// validateSecretKey: same shape as validatePublicKey.
const vsk = validateSecretKey(sk);
if (vsk.ok) {
  const _skOk: true = vsk.ok;
  // @ts-expect-error — the ok arm has no `reason` property.
  const _skNoReason: unknown = vsk.reason;
  void [_skOk, _skNoReason];
} else {
  const sreason: ValidateSecretKeyReason = vsk.reason;
  const _sreasons: ValidateSecretKeyReason[] = ['invalid-sk-type', 'invalid-sk-length', 'invalid-sk-encoding'];
  void [sreason, _sreasons];
}
validateSecretKey(null);
validateSecretKey(undefined);
validateSecretKey('not a key');
validateSecretKey([1, 2, 3]);

// Security utilities.
zeroize(sk);
const _zeroed: boolean = isZero(sk);

void [_pkBytes, _skBytes, _sigBytes, _seedBytes, smDet, smHex, rc, rcDet, ok, opened];
