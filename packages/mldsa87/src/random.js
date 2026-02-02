const MAX_BYTES = 65536;
const MAX_UINT32 = 0xffffffff;

function getWebCrypto() {
  if (typeof globalThis === 'object' && globalThis.crypto) return globalThis.crypto;
  return null;
}

export function randomBytes(size) {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError('size must be a non-negative integer');
  }
  if (size > MAX_UINT32) {
    throw new RangeError('requested too many random bytes');
  }
  if (size === 0) return new Uint8Array(0);

  const cryptoObj = getWebCrypto();
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    const out = new Uint8Array(size);
    for (let i = 0; i < size; i += MAX_BYTES) {
      cryptoObj.getRandomValues(out.subarray(i, Math.min(size, i + MAX_BYTES)));
    }
    if (size >= 16) {
      let acc = 0;
      for (let i = 0; i < 16; i++) acc |= out[i];
      if (acc === 0) throw new Error('getRandomValues returned all zeros');
    }
    return out;
  }

  throw new Error('Secure random number generation is not supported by this environment');
}
