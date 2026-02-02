import { expect } from 'chai';
import { randomBytes } from '../src/random.js';

const isNode = typeof process === 'object' && process !== null && process.versions && process.versions.node;
const itIfNode = isNode ? it : it.skip;
const itIfBrowser = isNode ? it.skip : it;

const originalGlobalThis = globalThis;
const originalState = {
  cryptoDesc: Object.getOwnPropertyDescriptor(originalGlobalThis, 'crypto'),
};

function setCrypto(value) {
  Object.defineProperty(originalGlobalThis, 'crypto', {
    value,
    configurable: true,
    writable: true,
    enumerable: true,
  });
}

function restoreGlobals() {
  if (originalState.cryptoDesc) {
    Object.defineProperty(originalGlobalThis, 'crypto', originalState.cryptoDesc);
  } else {
    delete originalGlobalThis.crypto;
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

  itIfNode('throws when getRandomValues returns all zeros for buffers >= 16 bytes', () => {
    const stubCrypto = {
      getRandomValues: (arr) => {
        // Leave buffer as all zeros (default Uint8Array state)
        return arr;
      },
    };
    setCrypto(stubCrypto);

    expect(() => randomBytes(32)).to.throw('getRandomValues returned all zeros');
  });

  itIfNode('does not throw all-zeros check for small buffers', () => {
    const stubCrypto = {
      getRandomValues: (arr) => {
        // Leave buffer as all zeros
        return arr;
      },
    };
    setCrypto(stubCrypto);

    // Buffers smaller than 16 bytes skip the zero check
    const out = randomBytes(8);
    expect(out.length).to.equal(8);
  });

  itIfNode('throws when crypto lacks getRandomValues', () => {
    setCrypto({});
    expect(() => randomBytes(1)).to.throw('Secure random number generation');
  });

  itIfNode('throws when no secure RNG is available', () => {
    setCrypto(undefined);
    expect(() => randomBytes(1)).to.throw('Secure random number generation');
  });
});
