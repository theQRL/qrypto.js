import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import { getSeed, treeHashSetup } from '../src/xmssFast.js';

describe('xmssFast', () => {
  describe('getSeed', () => {
    it('should update the seed variable with hashFunction SHA2_256', () => {
      const seed = new Uint8Array([2, 3, 5, 7, 4, 9, 1, 0]);
      getSeed(
        HASH_FUNCTION.SHA2_256,
        seed,
        new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]),
        1,
        new Uint32Array([3, 0, 0, 0, 0, 0, 2, 8])
      );
      const expectedSeed = new Uint8Array([220, 249, 92, 97, 226, 29, 208, 118]);

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should update the seed variable with hashFunction SHAKE_128', () => {
      const seed = new Uint8Array([2, 3, 5, 7, 4, 9, 1, 0]);
      getSeed(
        HASH_FUNCTION.SHAKE_128,
        seed,
        new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]),
        1,
        new Uint32Array([3, 0, 0, 0, 0, 0, 2, 8])
      );
      const expectedSeed = new Uint8Array([52, 91, 189, 158, 58, 60, 154, 95]);

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should update the seed variable with hashFunction SHAKE_256', () => {
      const seed = new Uint8Array([2, 3, 5, 7, 4, 9, 1, 0]);
      getSeed(
        HASH_FUNCTION.SHAKE_256,
        seed,
        new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]),
        1,
        new Uint32Array([3, 0, 0, 0, 0, 0, 2, 8])
      );
      const expectedSeed = new Uint8Array([28, 88, 226, 254, 193, 12, 174, 167]);

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should return back all the arguments passed to it, as an object', () => {
      const paramHashFunction = HASH_FUNCTION.SHAKE_256;
      const paramSeed = new Uint8Array([2, 3, 5, 7, 4, 9, 1, 0]);
      const paramSkSeed = new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]);
      const paramN = new Uint32Array([1])[0];
      const paramAddr = new Uint32Array([3, 0, 0, 0, 0, 0, 2, 8]);
      const { hashFunction, seed, skSeed, n, addr } = getSeed(
        paramHashFunction,
        paramSeed,
        paramSkSeed,
        paramN,
        paramAddr
      );

      expect(paramHashFunction).to.equal(hashFunction);
      expect(paramSeed).to.equal(seed);
      expect(paramSkSeed).to.equal(skSeed);
      expect(paramN).to.equal(n);
      expect(paramAddr).to.equal(addr);
    });
  });

  xdescribe('genLeafWOTS', () => {
    it('TODO', () => {});
  });

  xdescribe('treeHashSetup', () => {
    it('TODO: should return back all the arguments passed to it, as an object', () => {
      const paramHashFunction = HASH_FUNCTION.SHAKE_128;
      const paramNode = new Uint8Array([2, 3, 5, 7, 4, 9, 1, 0]);
      const paramIndex = new Uint32Array([1])[0];
      const paramBdsState = newBDSState(4, 2, 6);
      const paramSkSeed = new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]);
      const paramXmssParams = newXMSSParams(2, 4, 6, 8);
      const paramPubSeed = new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]);
      const paramAddr = new Uint32Array([2, 5, 1, 9, 4, 9, 1, 0]);
      const { hashFunction, node, index, bdsState, skSeed, xmssParams, pubSeed, addr } = treeHashSetup(
        paramHashFunction,
        paramNode,
        paramIndex,
        paramBdsState,
        paramSkSeed,
        paramXmssParams,
        paramPubSeed,
        paramAddr
      );

      expect(paramHashFunction).to.equal(hashFunction);
    });
  });

  xdescribe('XMSSFastGenKeyPair', () => {
    it('TODO', () => {});
  });
});
