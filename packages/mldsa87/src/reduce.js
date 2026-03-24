import { Q, QInv } from './const.js';

export function montgomeryReduce(a) {
  let t = BigInt.asIntN(32, BigInt.asIntN(64, BigInt.asIntN(32, a)) * BigInt(QInv));
  t = BigInt.asIntN(32, (a - t * BigInt(Q)) >> 32n);
  return t;
}

// Partial reduction modulo Q. Input must satisfy |a| < 2^31 - 2^22.
// Output is in (-Q, Q). Mirrors the reference C implementation.
export function reduce32(a) {
  let t = (a + (1 << 22)) >> 23;
  t = a - t * Q;
  return t;
}

// Conditional add Q: if a is negative, add Q. Input must satisfy -Q < a < 2^31.
// Output is in [0, Q). Mirrors the reference C implementation.
export function cAddQ(a) {
  let ar = a;
  ar += (ar >> 31) & Q;
  return ar;
}
