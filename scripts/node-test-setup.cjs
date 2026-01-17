const { webcrypto, randomBytes } = require('crypto');

if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
  if (webcrypto && typeof webcrypto.getRandomValues === 'function') {
    globalThis.crypto = webcrypto;
  } else if (typeof randomBytes === 'function') {
    globalThis.crypto = {
      getRandomValues: (arr) => {
        if (!(arr instanceof Uint8Array)) {
          throw new TypeError('getRandomValues expects a Uint8Array');
        }
        const buf = randomBytes(arr.length);
        arr.set(buf);
        return arr;
      },
    };
  }
}
