import { expect } from 'chai';
import { randomBytes } from '../src/random.js';

const isNode = typeof process === 'object' && process !== null && process.versions && process.versions.node;
const itIfNode = isNode ? it : it.skip;
const itIfBrowser = isNode ? it.skip : it;

const originalGlobalThis = globalThis;
const originalState = {
  self: originalGlobalThis.self,
  window: originalGlobalThis.window,
  global: originalGlobalThis.global,
  module: originalGlobalThis.module,
  require: originalGlobalThis.require,
  msCrypto: originalGlobalThis.msCrypto,
  cryptoDesc: Object.getOwnPropertyDescriptor(originalGlobalThis, 'crypto'),
  processDesc: Object.getOwnPropertyDescriptor(originalGlobalThis, 'process'),
};

function setGlobalThisValue(value) {
  originalGlobalThis.globalThis = value;
}

function setCrypto(value) {
  Object.defineProperty(originalGlobalThis, 'crypto', {
    value,
    configurable: true,
    writable: true,
    enumerable: true,
  });
}

function setProcess(value) {
  Object.defineProperty(originalGlobalThis, 'process', {
    value,
    configurable: true,
    writable: true,
    enumerable: false,
  });
}

function restoreGlobals() {
  setGlobalThisValue(originalGlobalThis);
  originalGlobalThis.self = originalState.self;
  originalGlobalThis.window = originalState.window;
  originalGlobalThis.global = originalState.global;
  originalGlobalThis.module = originalState.module;
  originalGlobalThis.require = originalState.require;

  if (originalState.cryptoDesc) {
    Object.defineProperty(originalGlobalThis, 'crypto', originalState.cryptoDesc);
  } else {
    delete originalGlobalThis.crypto;
  }

  if (originalState.processDesc) {
    Object.defineProperty(originalGlobalThis, 'process', originalState.processDesc);
  } else {
    delete originalGlobalThis.process;
  }

  if (originalState.msCrypto === undefined) {
    delete originalGlobalThis.msCrypto;
  } else {
    originalGlobalThis.msCrypto = originalState.msCrypto;
  }
}

describe('randomBytes', () => {
  if (isNode) {
    beforeEach(restoreGlobals);
    afterEach(restoreGlobals);
  }

  it('returns empty Uint8Array for size 0', () => {
    const out = randomBytes(0);
    expect(out).to.be.instanceOf(Uint8Array);
    expect(out.length).to.equal(0);
  });

  it('throws on invalid size', () => {
    expect(() => randomBytes(-1)).to.throw(RangeError);
    expect(() => randomBytes(1.5)).to.throw(RangeError);
  });

  it('throws on too-large size', () => {
    expect(() => randomBytes(0xffffffff + 1)).to.throw(RangeError);
  });

  itIfBrowser('uses Web Crypto in browsers', () => {
    const out = randomBytes(32);
    expect(out).to.be.instanceOf(Uint8Array);
    expect(out.length).to.equal(32);
  });

  itIfNode('uses globalThis.crypto.getRandomValues and chunks', () => {
    const calls = [];
    const stubCrypto = {
      getRandomValues: (arr) => {
        calls.push(arr.length);
        arr.fill(0xab);
        return arr;
      },
    };
    setCrypto(stubCrypto);

    const out = randomBytes(70000);
    expect(out.length).to.equal(70000);
    expect(calls).to.deep.equal([65536, 4464]);
    expect(out[0]).to.equal(0xab);
    expect(out[out.length - 1]).to.equal(0xab);
  });

  itIfNode('uses msCrypto when crypto is unavailable', () => {
    const calls = [];
    const stubCrypto = {
      getRandomValues: (arr) => {
        calls.push(arr.length);
        arr.fill(0xcd);
        return arr;
      },
    };
    setCrypto(undefined);
    originalGlobalThis.msCrypto = stubCrypto;

    const out = randomBytes(8);
    expect(out.length).to.equal(8);
    expect(out[0]).to.equal(0xcd);
    expect(calls).to.deep.equal([8]);
  });

  itIfNode('uses self when globalThis is unavailable', () => {
    const stubCrypto = {
      getRandomValues: (arr) => {
        arr.fill(0x11);
        return arr;
      },
    };
    originalGlobalThis.self = { crypto: stubCrypto };
    originalGlobalThis.window = undefined;
    setGlobalThisValue(undefined);

    const out = randomBytes(4);
    expect(out[0]).to.equal(0x11);
  });

  itIfNode('uses window when globalThis and self are unavailable', () => {
    const stubCrypto = {
      getRandomValues: (arr) => {
        arr.fill(0x22);
        return arr;
      },
    };
    originalGlobalThis.self = undefined;
    originalGlobalThis.window = { crypto: stubCrypto };
    setGlobalThisValue(undefined);

    const out = randomBytes(4);
    expect(out[0]).to.equal(0x22);
  });

  itIfNode('uses global when globalThis, self, and window are unavailable', () => {
    const stubCrypto = {
      getRandomValues: (arr) => {
        arr.fill(0x33);
        return arr;
      },
    };
    setCrypto(stubCrypto);
    originalGlobalThis.self = undefined;
    originalGlobalThis.window = undefined;
    setGlobalThisValue(undefined);

    const out = randomBytes(4);
    expect(out[0]).to.equal(0x33);
  });

  itIfNode('falls back when crypto object lacks getRandomValues', () => {
    setCrypto({});
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = {
      require: (name) => {
        expect(name).to.equal('crypto');
        return {
          randomBytes: (size) => {
            const out = new Uint8Array(size);
            out.fill(0x7f);
            return out;
          },
        };
      },
    };

    const out = randomBytes(3);
    expect(out[0]).to.equal(0x7f);
  });

  itIfNode('falls back to module.createRequire when module.require is missing', () => {
    setCrypto(undefined);
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = {
      createRequire: (url) => {
        expect(typeof url).to.equal('string');
        return (name) => {
          expect(name).to.equal('crypto');
          return {
            randomBytes: (size) => {
              const out = new Uint8Array(size);
              out.fill(0x66);
              return out;
            },
          };
        };
      },
    };

    const out = randomBytes(2);
    expect(out[0]).to.equal(0x66);
  });

  itIfNode('falls back to require when module is missing', () => {
    setCrypto(undefined);
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = undefined;
    originalGlobalThis.require = (name) => {
      expect(name).to.equal('crypto');
      return {
        randomBytes: (size) => {
          const out = new Uint8Array(size);
          out.fill(0x55);
          return out;
        },
      };
    };

    const out = randomBytes(2);
    expect(out[0]).to.equal(0x55);
  });

  itIfNode('throws when module returns no randomBytes', () => {
    setCrypto(undefined);
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = { require: () => ({}) };

    expect(() => randomBytes(1)).to.throw('Secure random number generation');
  });

  itIfNode('throws when module require throws', () => {
    setCrypto(undefined);
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = {
      require: () => {
        throw new Error('boom');
      },
    };

    expect(() => randomBytes(1)).to.throw('Secure random number generation');
  });

  itIfNode('throws when require is unavailable in Node', () => {
    setCrypto(undefined);
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = undefined;
    originalGlobalThis.require = undefined;

    expect(() => randomBytes(1)).to.throw('Secure random number generation');
  });

  itIfNode('throws when no secure RNG is available', () => {
    setCrypto(undefined);
    originalGlobalThis.msCrypto = undefined;
    originalGlobalThis.module = undefined;
    originalGlobalThis.require = undefined;
    originalGlobalThis.self = undefined;
    originalGlobalThis.window = undefined;
    originalGlobalThis.global = undefined;
    setGlobalThisValue(undefined);
    setProcess(undefined);

    expect(() => randomBytes(1)).to.throw('Secure random number generation');
  });
});
