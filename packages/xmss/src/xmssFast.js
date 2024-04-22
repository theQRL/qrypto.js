/**
 * @param {String} hashFunction
 * @param {Uint8Array} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {Uint8Array} bdsState
 * @param {Uint8Array} seed
 */
export function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
  if (xmssParams.h % 2 === 1) {
    throw new Error('Not a valid h, only even numbers supported! Try again with an even number');
  }

  const n = xmssParams.n;

  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;

  const randombits = new Uint8Array(3 * n);
  // misc.SHAKE256(randombits, seed[:])
}
