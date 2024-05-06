import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import { XMSSFastGenKeyPair, expandSeed, genChain, getSeed, hashF, treeHashSetup } from '../src/xmssFast.js';

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

  describe('hashF', () => {
    it('should set the result to the out variable, with SHAKE_128', () => {
      const out = new Uint8Array([3, 5, 1, 2, 7, 2, 7, 3]);
      const input = new Uint8Array([1, 3, 4, 4, 3, 2, 2, 7, 3]);
      const pubSeed = new Uint8Array([9, 2, 4, 5, 7, 4, 4, 3, 2, 2, 7, 3]);
      const addr = new Uint32Array([7, 4, 8, 2, 6, 0, 2, 5]);
      const n = 2;
      const expectedOut = new Uint8Array([116, 78, 210, 153, 143, 44, 226, 60]);
      const expectedInput = new Uint8Array([1, 3, 4, 4, 3, 2, 2, 7, 3]);
      const expectedPubSeed = new Uint8Array([9, 2, 4, 5, 7, 4, 4, 3, 2, 2, 7, 3]);
      const expectedAddr = new Uint32Array([7, 4, 8, 2, 6, 0, 2, 1]);
      hashF(HASH_FUNCTION.SHAKE_128, out, input, pubSeed, addr, n);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should set the result to the out variable, with SHA2_256', () => {
      const out = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const pubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const addr = new Uint32Array([4, 3, 2, 2, 7, 3, 2, 9]);
      const n = 32;
      const expectedOut = new Uint8Array([
        83, 91, 26, 111, 69, 189, 212, 121, 108, 125, 181, 168, 17, 241, 17, 230, 56, 127, 47, 57, 163, 111, 24, 196,
        47, 222, 103, 251, 212, 239, 249, 202, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const expectedPubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const expectedAddr = new Uint32Array([4, 3, 2, 2, 7, 3, 2, 1]);
      hashF(HASH_FUNCTION.SHA2_256, out, out, pubSeed, addr, n);

      expect(out).to.deep.equal(expectedOut);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('genChain', () => {
    it('should generate chain in the out variable, with SHA2_256 hashing', () => {
      const out = new Uint8Array([
        3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const input = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1,
        3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3,
      ]);
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const addr = new Uint32Array([4, 3, 2, 2, 7, 3, 9, 9]);
      const expectedOut = new Uint8Array([
        197, 123, 154, 206, 7, 143, 128, 162, 193, 109, 38, 180, 195, 173, 174, 146, 36, 234, 80, 133, 124, 153, 70,
        115, 58, 80, 76, 86, 193, 191, 221, 51, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const expectedInput = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1,
        3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3,
      ]);
      const expectedPubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const expectedAddr = new Uint32Array([4, 3, 2, 2, 7, 3, 4, 1]);
      genChain(HASH_FUNCTION.SHA2_256, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate chain in the out variable, with SHAKE_128 hashing', () => {
      const out = new Uint8Array([
        3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const input = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1,
        3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3,
      ]);
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const addr = new Uint32Array([4, 3, 2, 2, 7, 3, 9, 9]);
      const expectedOut = new Uint8Array([
        126, 158, 240, 254, 2, 207, 160, 28, 89, 7, 124, 212, 241, 132, 115, 192, 89, 122, 120, 55, 111, 108, 39, 12,
        245, 8, 193, 38, 121, 9, 182, 22, 88, 25, 33, 165, 206, 27, 78, 209, 188, 168, 169, 152, 123, 89, 28, 156, 221,
        219, 139, 155, 187, 208, 187, 224,
      ]);
      const expectedInput = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1,
        3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3,
      ]);
      const expectedPubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const expectedAddr = new Uint32Array([4, 3, 2, 2, 7, 3, 4, 1]);
      genChain(HASH_FUNCTION.SHAKE_128, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate chain in the out variable, with SHAKE_256 hashing', () => {
      const out = new Uint8Array([
        3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const input = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1,
        3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3,
      ]);
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const addr = new Uint32Array([4, 3, 2, 2, 7, 3, 9, 9]);
      const expectedOut = new Uint8Array([
        121, 146, 54, 55, 196, 31, 10, 12, 19, 109, 71, 78, 5, 168, 158, 206, 238, 140, 113, 6, 130, 213, 31, 76, 12,
        144, 71, 101, 230, 114, 67, 227, 169, 137, 68, 82, 97, 135, 175, 221, 70, 21, 69, 124, 120, 36, 198, 23, 15, 20,
        90, 202, 78, 187, 105, 87,
      ]);
      const expectedInput = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1,
        3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3,
      ]);
      const expectedPubSeed = new Uint8Array([
        4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5,
        7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8,
      ]);
      const expectedAddr = new Uint32Array([4, 3, 2, 2, 7, 3, 4, 1]);
      genChain(HASH_FUNCTION.SHAKE_256, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
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
