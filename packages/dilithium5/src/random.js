const MAX_BYTES = 65536;
const MAX_UINT32 = 0xffffffff;

function getGlobalScope() {
  if (typeof globalThis === 'object') return globalThis;
  if (typeof self === 'object') return self;
  if (typeof window === 'object') return window;
  if (typeof global === 'object') return global;
  return {};
}

function getWebCrypto() {
  const scope = getGlobalScope();
  return scope.crypto || scope.msCrypto || null;
}

function getNodeRandomBytes() {
  /* c8 ignore next */
  const isNode = typeof process === 'object' && process !== null && process.versions && process.versions.node;
  if (!isNode) return null;

  const req =
    typeof module !== 'undefined' && module && typeof module.require === 'function'
      ? module.require.bind(module)
      : typeof module !== 'undefined' && module && typeof module.createRequire === 'function'
        ? module.createRequire(import.meta.url)
        : typeof require === 'function'
          ? require
          : null;
  if (!req) return null;

  try {
    const nodeCrypto = req('crypto');
    if (nodeCrypto && typeof nodeCrypto.randomBytes === 'function') {
      return nodeCrypto.randomBytes;
    }
  } catch {
    return null;
  }

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
    return out;
  }

  const nodeRandomBytes = getNodeRandomBytes();
  if (nodeRandomBytes) {
    return nodeRandomBytes(size);
  }

  throw new Error('Secure random number generation is not supported by this environment');
}
