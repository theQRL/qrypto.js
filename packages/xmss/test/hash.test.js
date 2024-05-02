import { expect } from 'chai';
import { describe, it, xit } from 'mocha';
import { HASH_FUNCTION } from '../src/constants.js';
import { coreHash, hashH, prf } from '../src/hash.js';

describe('hash', () => {
  describe('coreHash', () => {
    it('should generate coreHash output for the hashFunction SHA2_256', () => {
      const outValue = new Uint8Array([4, 7, 8, 2, 6, 9, 2]);
      coreHash(
        HASH_FUNCTION.SHA2_256,
        outValue,
        2,
        new Uint8Array([1, 0, 0, 0, 5, 1]),
        6,
        new Uint8Array([9, 9, 9, 9]),
        4,
        9
      );
      const expectedOutValue = new Uint8Array([194, 214, 96, 196, 50, 145, 184]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate coreHash output for the hashFunction SHAKE_128', () => {
      const outValue = new Uint8Array([1, 2, 3, 4, 5]);
      coreHash(HASH_FUNCTION.SHAKE_128, outValue, 5, new Uint8Array([0, 0, 0]), 3, new Uint8Array([4, 5, 6]), 3, 4);
      const expectedOutValue = new Uint8Array([115, 1, 116, 33, 66]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate coreHash output for the hashFunction SHAKE_256', () => {
      const outValue = new Uint8Array([8, 4, 9, 1, 0, 1, 0]);
      coreHash(
        HASH_FUNCTION.SHAKE_256,
        outValue,
        7,
        new Uint8Array([6, 3]),
        2,
        new Uint8Array([9, 7, 8, 1, 5, 8]),
        6,
        1
      );
      const expectedOutValue = new Uint8Array([50, 69, 218, 59, 239, 102, 54]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });
  });

  describe('prf', () => {
    it('should generate prf output for the hashFunction SHA2_256', () => {
      const outValue = new Uint8Array([8, 4, 9, 1, 0, 1, 0]);
      prf(
        HASH_FUNCTION.SHA2_256,
        outValue,
        new Uint8Array([
          2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 3, 4,
        ]),
        new Uint8Array([6, 3, 2]),
        2
      );
      const expectedOutValue = new Uint8Array([69, 154, 42, 118, 65, 97, 150]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate prf output for the hashFunction SHAKE_128', () => {
      const outValue = new Uint8Array([8, 4, 9, 1, 0, 1, 0]);
      prf(
        HASH_FUNCTION.SHAKE_128,
        outValue,
        new Uint8Array([
          2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 3, 4,
        ]),
        new Uint8Array([6, 3, 2]),
        2
      );
      const expectedOutValue = new Uint8Array([151, 162, 185, 97, 255, 51, 61]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate prf output for the hashFunction SHAKE_256', () => {
      const outValue = new Uint8Array([8, 4, 9, 1, 0, 1, 0]);
      prf(
        HASH_FUNCTION.SHAKE_256,
        outValue,
        new Uint8Array([
          2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 2, 4, 5, 1, 4, 6, 7, 8, 9, 2, 3, 4,
        ]),
        new Uint8Array([6, 3, 2]),
        2
      );
      const expectedOutValue = new Uint8Array([229, 148, 107, 211, 209, 43, 245]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });
  });

  describe('hashH', () => {
    it('should generate prf output for the hashFunction SHA2_256', () => {
      const outValue = new Uint8Array([8, 4, 9, 1, 0, 1, 0]);
      hashH(
        HASH_FUNCTION.SHA2_256,
        outValue,
        new Uint8Array([2, 4, 3, 6]),
        new Uint8Array([8, 4, 3, 2]),
        new Uint32Array([3, 7, 2, 7, 2, 8, 7, 3]),
        new Uint32Array([2])[0]
      );
      const expectedOutValue = new Uint8Array([251, 62, 233, 104, 61, 163, 240]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate prf output for the hashFunction SHAKE_128', () => {
      const outValue = new Uint8Array([8, 1, 0, 3, 6, 8, 9, 2, 6, 8]);
      hashH(
        HASH_FUNCTION.SHAKE_128,
        outValue,
        new Uint8Array([2, 4, 3, 4, 6, 8, 6]),
        new Uint8Array([8, 4, 4, 43, 2]),
        new Uint32Array([3, 7, 2, 8, 7, 3, 0, 0]),
        new Uint32Array([3])[0]
      );
      const expectedOutValue = new Uint8Array([243, 139, 85, 6, 180, 216, 43, 72, 46, 11]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate prf output for the hashFunction SHAKE_256', () => {
      const outValue = new Uint8Array([2, 3, 5, 7, 8, 9, 1, 0]);
      hashH(
        HASH_FUNCTION.SHAKE_256,
        outValue,
        new Uint8Array([2, 3, 6]),
        new Uint8Array([4, 3, 2]),
        new Uint32Array([3, 0, 0, 0, 0, 0, 2, 8]),
        new Uint32Array([1])[0]
      );
      const expectedOutValue = new Uint8Array([149, 194, 107, 177, 208, 102, 106, 74]);

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should return back all the arguments passed to it, as an object', () => {
      const paramHashFunction = HASH_FUNCTION.SHAKE_256;
      const paramOut = new Uint8Array([5, 1, 6, 3, 6]);
      const paramInput = new Uint8Array([2, 5, 1, 6, 3, 6]);
      const paramPubSeed = new Uint8Array([2, 5, 1, 5, 1, 6, 3, 6]);
      const paramAddr = new Uint32Array([3, 5, 1, 2, 6, 8, 3, 2]);
      const paramN = new Uint32Array([3])[0];
      const { hashFunction, out, input, pubSeed, addr, n } = hashH(
        paramHashFunction,
        paramOut,
        paramInput,
        paramPubSeed,
        paramAddr,
        paramN
      );

      expect(paramHashFunction).to.equal(hashFunction);
      expect(paramOut).to.deep.equal(out);
      expect(paramInput).to.equal(input);
      expect(paramPubSeed).to.equal(pubSeed);
      expect(paramAddr).to.equal(addr);
      expect(paramN).to.equal(n);
    });
  });
});
