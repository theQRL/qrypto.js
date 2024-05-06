import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import { XMSSFastGenKeyPair, expandSeed, getSeed, treeHashSetup } from '../src/xmssFast.js';

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

  describe('expandSeed', () => {
    it('should expand the outseeds based on the inseeds provided', () => {
      const outSeeds = new Uint8Array([3, 5, 1, 2, 7, 2, 7, 3]);
      const inSeeds = new Uint8Array([9, 2, 1, 3, 4, 4, 3, 2, 2, 7, 3]);
      const n = 2;
      const len = 3;
      const expectedOutSeeds = new Uint8Array([74, 220, 103, 206, 51, 210, 7, 3]);
      const expectedInSeeds = new Uint8Array([9, 2, 1, 3, 4, 4, 3, 2, 2, 7, 3]);
      expandSeed(HASH_FUNCTION.SHAKE_256, outSeeds, inSeeds, n, len);

      expect(outSeeds).to.deep.equal(expectedOutSeeds);
      expect(inSeeds).to.deep.equal(expectedInSeeds);
    });
  });

  xdescribe('wOTSPKGen', () => {
    it('TODO', () => {});
  });

  xdescribe('genLeafWOTS', () => {
    it('TODO', () => {});
  });

  xdescribe('TODO: treeHashSetup', () => {
    it('TODO: should return back all the arguments passed to it, as an object', () => {
      const paramHashFunction = HASH_FUNCTION.SHAKE_128;
      const paramNode = new Uint8Array([2, 3, 5, 7, 4, 9, 1, 0]);
      const paramIndex = new Uint32Array([1])[0];
      const paramBdsState = newBDSState(4, 2, 6);
      const paramSkSeed = new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]);
      const paramXmssParams = newXMSSParams(2, 4, 6, 8);
      const paramPubSeed = new Uint8Array([2, 5, 1, 9, 4, 9, 1, 0]);
      const paramAddr = new Uint32Array([2, 5, 1, 9, 4, 9, 1, 0]);
      treeHashSetup(
        paramHashFunction,
        paramNode,
        paramIndex,
        paramBdsState,
        paramSkSeed,
        paramXmssParams,
        paramPubSeed,
        paramAddr
      );

      // TODO assert something here
    });
  });

  xdescribe('TODO: XMSSFastGenKeyPair', () => {
    it('should generate secret key and public key', () => {
      const height = 2;
      const k = 2;
      const w = 16;
      const n = 32;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = new Uint8Array(64);
      const sk = new Uint8Array(132);
      const seed = new Uint8Array([
        3, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2,
        6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6,
      ]);
      const expectedPk = new Uint8Array([
        105, 62, 53, 109, 98, 168, 76, 83, 245, 22, 47, 54, 128, 31, 25, 180, 69, 245, 135, 107, 112, 173, 60, 22, 168,
        40, 153, 30, 207, 158, 221, 130, 37, 191, 167, 192, 69, 130, 84, 177, 131, 34, 220, 71, 48, 210, 210, 2, 141,
        23, 83, 106, 38, 201, 88, 150, 127, 234, 114, 51, 113, 1, 159, 19,
      ]);
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 19, 243, 36, 100, 26, 233, 177, 174, 244, 177, 24, 144, 221, 121, 24, 162, 231, 253, 61, 131, 49,
        227, 61, 249, 176, 167, 100, 223, 227, 176, 71, 61, 149, 111, 75, 206, 44, 203, 93, 233, 72, 74, 126, 44, 240,
        104, 125, 176, 115, 245, 29, 227, 131, 107, 134, 252, 47, 200, 237, 169, 35, 144, 56, 15, 37, 191, 167, 192, 69,
        130, 84, 177, 131, 34, 220, 71, 48, 210, 210, 2, 141, 23, 83, 106, 38, 201, 88, 150, 127, 234, 114, 51, 113, 1,
        159, 19, 105, 62, 53, 109, 98, 168, 76, 83, 245, 22, 47, 54, 128, 31, 25, 180, 69, 245, 135, 107, 112, 173, 60,
        22, 168, 40, 153, 30, 207, 158, 221, 130,
      ]);
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
    });
  });
});
