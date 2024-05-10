import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newTreeHashInst, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import {
  XMSSFastGenKeyPair,
  bdsRound,
  bdsTreeHashUpdate,
  expandSeed,
  genChain,
  genLeafWOTS,
  getSeed,
  hashF,
  lTree,
  treeHashMinHeightOnStack,
  treeHashSetup,
  treeHashUpdate,
  wOTSPKGen,
} from '../src/xmssFast.js';

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

  describe('wOTSPKGen', () => {
    it('should generate public key, with SHA2_256 hashing', () => {
      const pk = new Uint8Array([
        4, 2, 2, 4, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9, 2, 1, 6, 9, 0, 4, 22, 33, 55, 88, 11, 33, 9, 0, 4, 22, 33,
        55, 88, 11, 33, 6, 8, 9, 2, 4, 2, 2, 4, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9, 2, 1, 6, 9, 0, 4, 22, 33, 55,
        88, 11, 33, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9, 2, 4, 2, 2, 4, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9,
        2, 1, 6, 9, 0, 4, 22, 33, 55, 88, 11, 33, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9, 2,
      ]);
      const sk = new Uint8Array([4, 3, 2, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5]);
      const w = 5;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([8, 3, 1, 6, 9, 0, 2, 1, 3, 5]);
      const addr = new Uint32Array([22, 44, 5, 7, 33, 7, 8, 22]);
      const expectedPk = new Uint8Array([
        51, 34, 15, 145, 3, 213, 147, 54, 144, 153, 183, 51, 120, 111, 217, 252, 116, 29, 171, 59, 129, 38, 22, 33, 55,
        88, 11, 33, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9, 2, 4, 2, 2, 4, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9,
        2, 1, 6, 9, 0, 4, 22, 33, 55, 88, 11, 33, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9, 2, 4, 2, 2, 4, 9, 0, 4, 22,
        33, 55, 88, 11, 33, 6, 8, 9, 2, 1, 6, 9, 0, 4, 22, 33, 55, 88, 11, 33, 9, 0, 4, 22, 33, 55, 88, 11, 33, 6, 8, 9,
        2,
      ]);
      const expectedSk = new Uint8Array([4, 3, 2, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5]);
      const expectedPubSeed = new Uint8Array([8, 3, 1, 6, 9, 0, 2, 1, 3, 5]);
      const expectedAddr = new Uint32Array([22, 44, 5, 7, 33, 10, 3, 1]);
      wOTSPKGen(HASH_FUNCTION.SHA2_256, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate public key, with SHAKE_128 hashing', () => {
      const pk = new Uint8Array([
        3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3,
        3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3,
        5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1,
        7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5,
        1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2,
        7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3,
        7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7,
        3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7,
        3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const sk = new Uint8Array([1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5]);
      const w = 2;
      const n = 3;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([6, 3, 1, 5, 6, 3]);
      const addr = new Uint32Array([8, 44, 5, 7, 33, 7, 8, 22]);
      const expectedPk = new Uint8Array([
        118, 160, 162, 77, 89, 9, 204, 243, 79, 41, 232, 61, 35, 124, 3, 219, 76, 76, 79, 31, 177, 157, 51, 254, 23,
        180, 18, 9, 171, 58, 19, 249, 90, 25, 16, 22, 48, 87, 160, 134, 36, 9, 122, 4, 114, 106, 175, 16, 110, 109, 134,
        162, 96, 22, 128, 119, 167, 24, 20, 54, 61, 63, 208, 192, 90, 188, 36, 12, 178, 62, 29, 212, 28, 189, 172, 99,
        142, 214, 110, 174, 141, 159, 177, 47, 29, 113, 141, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7,
        3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7,
        3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3,
        3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5,
        1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3,
        5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1,
        2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3,
        3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const expectedSk = new Uint8Array([1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5]);
      const expectedPubSeed = new Uint8Array([6, 3, 1, 5, 6, 3]);
      const expectedAddr = new Uint32Array([8, 44, 5, 7, 33, 28, 0, 1]);
      wOTSPKGen(HASH_FUNCTION.SHAKE_128, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate public key, with SHAKE_256 hashing', () => {
      const pk = new Uint8Array([
        3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3,
        3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3,
        5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1,
        7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5,
        1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2,
        7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3,
        7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7,
        3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7,
        3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const sk = new Uint8Array([1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5]);
      const w = 8;
      const n = 7;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([4, 5, 3, 1, 3, 2, 2]);
      const addr = new Uint32Array([4, 3, 2, 2, 7, 3, 9, 9]);
      const expectedPk = new Uint8Array([
        58, 247, 208, 0, 173, 42, 153, 203, 172, 13, 253, 163, 44, 130, 132, 252, 46, 154, 178, 116, 157, 56, 229, 124,
        31, 53, 8, 59, 38, 87, 84, 5, 172, 81, 20, 228, 43, 225, 149, 154, 153, 89, 176, 235, 200, 32, 185, 54, 179,
        143, 212, 206, 131, 127, 46, 24, 34, 205, 36, 130, 159, 75, 166, 26, 200, 97, 28, 162, 219, 252, 220, 119, 218,
        112, 83, 127, 196, 72, 91, 172, 196, 11, 224, 36, 226, 10, 79, 35, 44, 141, 28, 167, 154, 120, 96, 94, 137, 24,
        170, 138, 166, 25, 241, 72, 200, 254, 188, 140, 166, 200, 129, 35, 45, 255, 206, 35, 30, 76, 163, 238, 17, 148,
        213, 18, 126, 204, 103, 242, 118, 43, 16, 255, 39, 166, 19, 220, 125, 231, 200, 31, 78, 77, 63, 147, 143, 41,
        30, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5,
        1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7,
        3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1,
        2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 7, 3, 3, 7, 2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 7, 3, 3, 7,
        2, 7, 3, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      const expectedSk = new Uint8Array([1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5]);
      const expectedPubSeed = new Uint8Array([4, 5, 3, 1, 3, 2, 2]);
      const expectedAddr = new Uint32Array([4, 3, 2, 2, 7, 20, 6, 1]);
      wOTSPKGen(HASH_FUNCTION.SHAKE_256, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('lTree', () => {
    it('should generate lTree, with SHA2_256 hashing', () => {
      const n = 2;
      const w = 3;
      const params = newWOTSParams(n, w);
      const leaf = new Uint8Array([
        33, 68, 9, 2, 45, 77, 5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99,
      ]);
      const wotsPk = new Uint8Array([
        56, 24, 78, 99, 33, 68, 56, 24, 78, 99, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 33, 68, 9, 2, 45, 77, 23, 56,
        24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7,
      ]);
      const pubSeed = new Uint8Array([5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99]);
      const addr = new Uint8Array([4, 3, 2, 2, 7, 3, 9, 9]);
      const expectedLeaf = new Uint8Array([
        154, 218, 9, 2, 45, 77, 5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99,
      ]);
      const expectedWotsPk = new Uint8Array([
        154, 218, 25, 64, 25, 64, 33, 169, 24, 247, 224, 242, 93, 40, 172, 222, 46, 234, 200, 229, 224, 242, 33, 68, 9,
        2, 45, 77, 23, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7,
      ]);
      const expectedPubSeed = new Uint8Array([
        5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99,
      ]);
      const expectedAddr = new Uint8Array([4, 3, 2, 2, 7, 5, 0, 2]);
      lTree(HASH_FUNCTION.SHA2_256, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate lTree, with SHAKE_128 hashing', () => {
      const n = 1;
      const w = 6;
      const params = newWOTSParams(n, w);
      const leaf = new Uint8Array([99, 4, 3, 45, 77, 2, 6, 8, 2, 9, 3, 8, 22, 79, 2]);
      const wotsPk = new Uint8Array([
        59, 2, 45, 77, 23, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33, 68,
        9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7,
        4, 6, 8, 2, 7, 5, 22, 3, 4, 77,
      ]);
      const pubSeed = new Uint8Array([
        5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24,
        78, 99,
      ]);
      const addr = new Uint8Array([9, 32, 2, 7, 3, 22, 9, 9]);
      const expectedLeaf = new Uint8Array([46, 4, 3, 45, 77, 2, 6, 8, 2, 9, 3, 8, 22, 79, 2]);
      const expectedWotsPk = new Uint8Array([
        46, 97, 72, 24, 23, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33,
        68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5,
        3, 7, 4, 6, 8, 2, 7, 5, 22, 3, 4, 77,
      ]);
      const expectedPubSeed = new Uint8Array([
        5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 5, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24,
        78, 99,
      ]);
      const expectedAddr = new Uint8Array([9, 32, 2, 7, 3, 3, 0, 2]);
      lTree(HASH_FUNCTION.SHAKE_128, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate lTree, with SHAKE_256 hashing', () => {
      const n = 1;
      const w = 6;
      const params = newWOTSParams(n, w);
      const leaf = new Uint8Array([6, 8, 2, 9, 3, 8, 22, 99, 4, 3, 45, 77, 2, 79, 2]);
      const wotsPk = new Uint8Array([
        68, 9, 2, 45, 77, 23, 56, 24, 78, 59, 2, 45, 77, 23, 56, 24, 78, 99, 33, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33, 68,
        9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7,
        4, 6, 8, 2, 7, 5, 22, 3, 4, 77,
      ]);
      const pubSeed = new Uint8Array([
        5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 55, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78,
        99,
      ]);
      const addr = new Uint8Array([44, 11, 6, 7, 3, 22, 9, 9]);
      const expectedLeaf = new Uint8Array([7, 8, 2, 9, 3, 8, 22, 99, 4, 3, 45, 77, 2, 79, 2]);
      const expectedWotsPk = new Uint8Array([
        7, 41, 112, 56, 77, 23, 56, 24, 78, 59, 2, 45, 77, 23, 56, 24, 78, 99, 33, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33,
        68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5, 3, 7, 4, 56, 24, 78, 99, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78, 99, 5,
        3, 7, 4, 6, 8, 2, 7, 5, 22, 3, 4, 77,
      ]);
      const expectedPubSeed = new Uint8Array([
        5, 3, 7, 9, 2, 7, 9, 2, 8, 2, 55, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 7, 33, 68, 9, 2, 45, 77, 23, 56, 24, 78,
        99,
      ]);
      const expectedAddr = new Uint8Array([44, 11, 6, 7, 3, 3, 0, 2]);
      lTree(HASH_FUNCTION.SHAKE_256, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('genLeafWOTS', () => {
    it('should generate leafWOTS, with SHA2_256 hashing', () => {
      const leaf = new Uint8Array([3, 5, 4, 7, 2, 6, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const skSeed = new Uint8Array([3, 5, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const xmssParams = newXMSSParams(2, 2, 5, 2);
      const pubSeed = new Uint8Array([3, 5, 1, 5, 1, 2, 5, 3, 6, 7, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const lTreeAddr = new Uint32Array([44, 11, 6, 7, 3, 22, 9, 9]);
      const otsAddr = new Uint32Array([44, 11, 6, 7, 22, 44, 9, 9]);
      const expectedLeaf = new Uint8Array([113, 175, 4, 7, 2, 6, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const expectedSkSeed = new Uint8Array([3, 5, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const expectedPubSeed = new Uint8Array([3, 5, 1, 5, 1, 2, 5, 3, 6, 7, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const expectedLTreeAddr = new Uint32Array([44, 11, 6, 7, 3, 4, 0, 2]);
      const expectedOtsAddr = new Uint32Array([44, 11, 6, 7, 22, 10, 3, 1]);
      genLeafWOTS(HASH_FUNCTION.SHA2_256, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });

    it('should generate leafWOTS, with SHAKE_128 hashing', () => {
      const leaf = new Uint8Array([8, 3, 5, 4, 7, 2, 6, 1, 5, 1, 2, 5, 3, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const skSeed = new Uint8Array([9, 3, 5, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const xmssParams = newXMSSParams(4, 3, 3, 9);
      const pubSeed = new Uint8Array([9, 5, 1, 5, 1, 2, 5, 3, 6, 7, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const lTreeAddr = new Uint32Array([44, 11, 6, 7, 37, 22, 9, 9]);
      const otsAddr = new Uint32Array([44, 11, 6, 7, 22, 44, 99, 9]);
      const expectedLeaf = new Uint8Array([
        114, 164, 49, 129, 7, 2, 6, 1, 5, 1, 2, 5, 3, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2,
      ]);
      const expectedSkSeed = new Uint8Array([9, 3, 5, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const expectedPubSeed = new Uint8Array([9, 5, 1, 5, 1, 2, 5, 3, 6, 7, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const expectedLTreeAddr = new Uint32Array([44, 11, 6, 7, 37, 6, 0, 2]);
      const expectedOtsAddr = new Uint32Array([44, 11, 6, 7, 22, 38, 1, 1]);
      genLeafWOTS(HASH_FUNCTION.SHAKE_128, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });

    it('should generate leafWOTS, with SHAKE_256 hashing', () => {
      const leaf = new Uint8Array([4, 3, 56, 7, 22, 44, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const skSeed = new Uint8Array([9, 3, 5, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 44, 86, 41]);
      const xmssParams = newXMSSParams(9, 7, 6, 5);
      const pubSeed = new Uint8Array([9, 44, 86, 41, 5, 1, 5, 1, 2, 5, 3, 6, 7, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6]);
      const lTreeAddr = new Uint32Array([44, 11, 6, 74, 37, 22, 9, 9]);
      const otsAddr = new Uint32Array([44, 11, 63, 7, 22, 44, 99, 9]);
      const expectedLeaf = new Uint8Array([21, 71, 160, 38, 68, 19, 241, 160, 86, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const expectedSkSeed = new Uint8Array([9, 3, 5, 1, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 44, 86, 41]);
      const expectedPubSeed = new Uint8Array([
        9, 44, 86, 41, 5, 1, 5, 1, 2, 5, 3, 6, 7, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6,
      ]);
      const expectedLTreeAddr = new Uint32Array([44, 11, 6, 74, 37, 6, 0, 2]);
      const expectedOtsAddr = new Uint32Array([44, 11, 63, 7, 22, 39, 4, 1]);
      genLeafWOTS(HASH_FUNCTION.SHAKE_256, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });
  });

  describe('treeHashSetup', () => {
    it('should setup tree hash, with SHA2_256 hashing', () => {
      const index = 5;
      const height = 3;
      const k = 3;
      const w = 7;
      const n = 3;
      const node = new Uint8Array([56, 7, 22, 44, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const bdsState = newBDSState(height, n, k);
      const skSeed = new Uint8Array([9, 7, 52, 4, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([56, 7, 22, 44, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 54]);
      const addr = new Uint32Array([88, 7, 22, 44, 86, 41, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const expectedNode = new Uint8Array([2, 31, 4, 44, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const expectedSkSeed = new Uint8Array([9, 7, 52, 4, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      const expectedPubSeed = new Uint8Array([56, 7, 22, 44, 86, 41, 2, 6, 8, 2, 7, 3, 5, 1, 2, 5, 3, 54]);
      const expectedAddr = new Uint32Array([88, 7, 22, 44, 86, 41, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2]);
      treeHashSetup(HASH_FUNCTION.SHA2_256, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should setup tree hash, with SHAKE_128 hashing', () => {
      const index = 7;
      const height = 4;
      const k = 2;
      const w = 5;
      const n = 9;
      const node = new Uint8Array([13, 11, 5, 8, 5, 13, 3, 2, 6, 15, 11, 8, 14, 11, 15, 14]);
      const bdsState = newBDSState(height, n, k);
      const skSeed = new Uint8Array([
        7, 16, 18, 11, 12, 6, 19, 15, 15, 6, 15, 1, 13, 17, 21, 1, 8, 19, 17, 6, 18, 5, 16,
      ]);
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        9, 3, 21, 13, 13, 11, 14, 20, 23, 25, 0, 0, 17, 18, 11, 9, 6, 10, 15, 14, 7, 11, 14, 15, 9, 6,
      ]);
      const addr = new Uint32Array([14, 7, 15, 7, 4, 7, 15, 11, 7, 15, 4, 9, 11, 5, 4, 2, 6]);
      const expectedNode = new Uint8Array([210, 218, 43, 76, 124, 84, 203, 50, 76, 15, 11, 8, 14, 11, 15, 14]);
      const expectedSkSeed = new Uint8Array([
        7, 16, 18, 11, 12, 6, 19, 15, 15, 6, 15, 1, 13, 17, 21, 1, 8, 19, 17, 6, 18, 5, 16,
      ]);
      const expectedPubSeed = new Uint8Array([
        9, 3, 21, 13, 13, 11, 14, 20, 23, 25, 0, 0, 17, 18, 11, 9, 6, 10, 15, 14, 7, 11, 14, 15, 9, 6,
      ]);
      const expectedAddr = new Uint32Array([14, 7, 15, 7, 4, 7, 15, 11, 7, 15, 4, 9, 11, 5, 4, 2, 6]);
      treeHashSetup(HASH_FUNCTION.SHAKE_128, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should setup tree hash, with SHAKE_256 hashing', () => {
      const index = 12;
      const height = 7;
      const k = 4;
      const w = 9;
      const n = 12;
      const node = new Uint8Array([0, 13, 3, 10, 11, 12, 2, 9, 10, 8, 11, 2, 5, 5, 3, 1]);
      const bdsState = newBDSState(height, n, k);
      const skSeed = new Uint8Array([12, 7, 16, 12, 1, 16, 12, 5, 3, 15, 14, 20, 13, 7, 21, 3, 0, 13, 7, 12, 3, 21, 4]);
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        16, 4, 24, 16, 4, 6, 16, 7, 19, 14, 13, 9, 3, 13, 10, 8, 0, 16, 16, 13, 4, 18, 20, 1, 8,
      ]);
      const addr = new Uint32Array([3, 6, 0, 12, 4, 0, 16, 2, 16, 0, 5, 10, 14, 13, 12, 7, 4]);
      const expectedNode = new Uint8Array([151, 183, 128, 14, 204, 52, 114, 135, 104, 226, 31, 18, 5, 5, 3, 1]);
      const expectedSkSeed = new Uint8Array([
        12, 7, 16, 12, 1, 16, 12, 5, 3, 15, 14, 20, 13, 7, 21, 3, 0, 13, 7, 12, 3, 21, 4,
      ]);
      const expectedPubSeed = new Uint8Array([
        16, 4, 24, 16, 4, 6, 16, 7, 19, 14, 13, 9, 3, 13, 10, 8, 0, 16, 16, 13, 4, 18, 20, 1, 8,
      ]);
      const expectedAddr = new Uint32Array([3, 6, 0, 12, 4, 0, 16, 2, 16, 0, 5, 10, 14, 13, 12, 7, 4]);
      treeHashSetup(HASH_FUNCTION.SHAKE_256, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('XMSSFastGenKeyPair', () => {
    it('should generate secret key and public key, with SHA2_256 hashing', () => {
      const height = 2;
      const k = 2;
      const w = 16;
      const n = 32;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = new Uint8Array([
        39, 18, 19, 24, 25, 30, 23, 42, 14, 60, 12, 31, 13, 39, 48, 15, 57, 60, 7, 30, 42, 40, 31, 54, 19, 18, 0, 1, 15,
        56, 2, 52, 12, 25, 14, 21, 56, 62, 15, 11, 19, 12, 49, 41, 32, 36, 34, 15, 4, 28, 29, 55, 0, 43, 1, 45, 35, 11,
        23, 36, 10, 9, 28, 15,
      ]);
      const sk = new Uint8Array([
        124, 72, 20, 90, 27, 101, 108, 75, 16, 116, 47, 4, 33, 96, 129, 61, 114, 60, 127, 13, 8, 44, 30, 96, 109, 46,
        48, 16, 31, 25, 88, 117, 71, 17, 89, 79, 83, 113, 113, 3, 1, 10, 114, 36, 24, 113, 93, 54, 37, 52, 22, 36, 90,
        43, 7, 30, 78, 76, 39, 84, 116, 125, 42, 91, 26, 46, 91, 61, 80, 46, 58, 97, 111, 81, 73, 33, 117, 102, 67, 22,
        97, 37, 95, 127, 86, 46, 78, 48, 81, 43, 30, 54, 115, 21, 48, 110, 42, 16, 46, 77, 10, 111, 81, 13, 94, 77, 122,
        10, 83, 6, 39, 90, 66, 35, 45, 21, 42, 23, 8, 104, 67, 2, 84, 21, 105, 19, 117, 7, 103, 63, 83, 102,
      ]);
      const seed = new Uint8Array([
        16, 38, 21, 32, 24, 41, 4, 42, 27, 36, 35, 20, 15, 14, 9, 30, 10, 32, 47, 36, 41, 37, 15, 31, 2, 6, 25, 14, 18,
        18, 35, 28, 35, 21, 1, 32, 30, 4, 30, 21, 18, 31, 11, 45, 45, 35, 33, 1,
      ]);
      const expectedPk = new Uint8Array([
        136, 168, 130, 198, 145, 179, 119, 87, 143, 43, 52, 134, 201, 189, 13, 214, 57, 61, 181, 215, 175, 119, 25, 165,
        223, 16, 108, 0, 215, 151, 151, 226, 131, 67, 227, 179, 207, 251, 13, 252, 56, 243, 206, 107, 239, 244, 222,
        166, 243, 99, 236, 211, 180, 132, 45, 11, 173, 45, 115, 37, 123, 15, 123, 158,
      ]);
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 2, 82, 169, 252, 31, 193, 255, 117, 221, 216, 202, 52, 188, 115, 32, 30, 172, 147, 1, 33, 164, 0,
        118, 44, 145, 127, 253, 34, 197, 96, 84, 240, 15, 180, 72, 83, 255, 121, 192, 47, 81, 170, 190, 170, 29, 98,
        158, 9, 237, 32, 195, 213, 159, 191, 85, 34, 34, 211, 233, 49, 16, 219, 224, 151, 131, 67, 227, 179, 207, 251,
        13, 252, 56, 243, 206, 107, 239, 244, 222, 166, 243, 99, 236, 211, 180, 132, 45, 11, 173, 45, 115, 37, 123, 15,
        123, 158, 136, 168, 130, 198, 145, 179, 119, 87, 143, 43, 52, 134, 201, 189, 13, 214, 57, 61, 181, 215, 175,
        119, 25, 165, 223, 16, 108, 0, 215, 151, 151, 226,
      ]);
      const expectedSeed = new Uint8Array([
        16, 38, 21, 32, 24, 41, 4, 42, 27, 36, 35, 20, 15, 14, 9, 30, 10, 32, 47, 36, 41, 37, 15, 31, 2, 6, 25, 14, 18,
        18, 35, 28, 35, 21, 1, 32, 30, 4, 30, 21, 18, 31, 11, 45, 45, 35, 33, 1,
      ]);
      XMSSFastGenKeyPair(HASH_FUNCTION.SHA2_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should generate secret key and public key, with SHAKE_128 hashing', () => {
      const height = 4;
      const k = 3;
      const w = 7;
      const n = 37;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = new Uint8Array([
        49, 20, 16, 52, 43, 27, 50, 59, 21, 26, 31, 17, 62, 45, 7, 49, 54, 21, 35, 34, 38, 8, 10, 17, 32, 56, 20, 61,
        62, 47, 5, 11, 50, 16, 30, 6, 6, 26, 34, 9, 8, 60, 63, 28, 18, 49, 61, 40, 34, 57, 26, 42, 17, 18, 8, 6, 25, 24,
        20, 0, 34, 18, 51, 22,
      ]);
      const sk = new Uint8Array([
        127, 31, 98, 30, 99, 10, 63, 79, 47, 97, 35, 27, 57, 35, 47, 25, 13, 3, 31, 61, 36, 62, 111, 110, 32, 16, 4,
        105, 56, 124, 29, 101, 76, 42, 118, 124, 74, 42, 51, 54, 112, 85, 38, 15, 54, 131, 94, 27, 33, 39, 43, 30, 33,
        62, 62, 131, 49, 57, 95, 5, 82, 41, 122, 40, 78, 39, 2, 13, 94, 61, 124, 128, 74, 100, 54, 110, 122, 100, 63,
        101, 62, 3, 23, 36, 88, 59, 61, 99, 92, 74, 49, 77, 20, 95, 85, 78, 66, 110, 92, 109, 62, 70, 5, 38, 54, 129,
        75, 7, 54, 14, 22, 79, 114, 66, 28, 46, 14, 80, 62, 91, 95, 102, 101, 50, 115, 88, 67, 50, 84, 36, 72, 29,
      ]);
      const seed = new Uint8Array([
        39, 35, 4, 39, 41, 6, 31, 36, 34, 28, 46, 24, 24, 42, 47, 35, 33, 6, 10, 46, 14, 32, 1, 30, 7, 47, 26, 28, 9, 7,
        31, 38, 12, 18, 43, 40, 28, 17, 39, 1, 36, 45, 0, 43, 33, 24, 15, 17,
      ]);
      const expectedPk = new Uint8Array([
        250, 135, 42, 79, 144, 169, 169, 137, 227, 139, 90, 202, 82, 45, 63, 38, 232, 183, 203, 31, 34, 187, 127, 55,
        110, 176, 97, 214, 104, 237, 87, 2, 22, 208, 214, 39, 142, 219, 205, 213, 248, 5, 206, 65, 39, 77, 12, 164, 181,
        35, 222, 136, 178, 154, 235, 98, 150, 194, 251, 62, 70, 5, 38, 54,
      ]);
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 34, 79, 45, 6, 182, 111, 65, 134, 127, 171, 25, 48, 230, 25, 235, 53, 68, 162, 157, 128, 100, 151,
        194, 243, 42, 15, 200, 241, 185, 232, 31, 85, 118, 137, 238, 179, 179, 219, 18, 168, 0, 50, 14, 93, 216, 3, 236,
        122, 150, 36, 225, 125, 47, 26, 74, 163, 218, 201, 26, 201, 188, 66, 238, 165, 112, 219, 35, 223, 254, 16, 190,
        9, 185, 246, 219, 205, 213, 248, 5, 206, 65, 39, 77, 12, 164, 181, 35, 222, 136, 178, 154, 235, 98, 150, 194,
        251, 62, 70, 5, 38, 54, 129, 75, 7, 54, 14, 22, 79, 114, 66, 28, 250, 135, 42, 79, 144, 169, 169, 137, 227, 139,
        90, 202, 82, 45, 63, 38, 232,
      ]);
      const expectedSeed = new Uint8Array([
        39, 35, 4, 39, 41, 6, 31, 36, 34, 28, 46, 24, 24, 42, 47, 35, 33, 6, 10, 46, 14, 32, 1, 30, 7, 47, 26, 28, 9, 7,
        31, 38, 12, 18, 43, 40, 28, 17, 39, 1, 36, 45, 0, 43, 33, 24, 15, 17,
      ]);
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_128, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should generate secret key and public key, with SHAKE_256 hashing', () => {
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
      const expectedSeed = new Uint8Array([
        3, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6, 2, 7, 3, 5, 1, 2, 5, 3, 2,
        6, 2, 7, 3, 5, 1, 2, 5, 3, 2, 6,
      ]);
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });
  });

  describe('treeHashUpdate', () => {
    it('should update tree hash, with SHA2_256 hashing', () => {
      const height = 5;
      const k = 3;
      const w = 9;
      const n = 4;
      const bdsState = newBDSState(height, n, k);
      const skSeed = new Uint8Array([12, 7, 16, 12, 1, 16, 12, 5, 3, 15, 14, 20, 13, 7, 21, 3, 0, 13, 7, 12, 3, 21, 4]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        16, 4, 24, 16, 4, 6, 16, 7, 19, 14, 13, 9, 3, 13, 10, 8, 0, 16, 16, 13, 4, 18, 20, 1, 8,
      ]);
      const addr = new Uint32Array([3, 6, 0, 12, 4, 0, 4, 5]);
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = new Uint8Array([74, 176, 65, 181]);
      const expectedSkSeed = new Uint8Array([
        12, 7, 16, 12, 1, 16, 12, 5, 3, 15, 14, 20, 13, 7, 21, 3, 0, 13, 7, 12, 3, 21, 4,
      ]);
      const expectedPubSeed = new Uint8Array([
        16, 4, 24, 16, 4, 6, 16, 7, 19, 14, 13, 9, 3, 13, 10, 8, 0, 16, 16, 13, 4, 18, 20, 1, 8,
      ]);
      const expectedAddr = new Uint32Array([3, 6, 0, 12, 4, 0, 4, 5]);
      treeHashUpdate(HASH_FUNCTION.SHA2_256, bdsState.treeHash[0], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[0]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should update tree hash, with SHAKE_128 hashing', () => {
      const height = 7;
      const k = 3;
      const w = 7;
      const n = 4;
      const bdsState = newBDSState(height, n, k);
      const skSeed = new Uint8Array([
        13, 9, 8, 15, 18, 17, 23, 7, 4, 6, 29, 29, 1, 24, 16, 8, 31, 22, 17, 10, 18, 10, 19, 9, 12, 12, 15, 31, 2, 27,
        26, 1,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        15, 21, 12, 1, 19, 20, 10, 1, 17, 10, 15, 4, 11, 2, 16, 16, 18, 12, 8, 17, 8, 5, 7, 9,
      ]);
      const addr = new Uint32Array([30, 13, 25, 0, 104, 44, 95, 110]);
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = new Uint8Array([69, 53, 168, 119]);
      const expectedSkSeed = new Uint8Array([
        13, 9, 8, 15, 18, 17, 23, 7, 4, 6, 29, 29, 1, 24, 16, 8, 31, 22, 17, 10, 18, 10, 19, 9, 12, 12, 15, 31, 2, 27,
        26, 1,
      ]);
      const expectedPubSeed = new Uint8Array([
        15, 21, 12, 1, 19, 20, 10, 1, 17, 10, 15, 4, 11, 2, 16, 16, 18, 12, 8, 17, 8, 5, 7, 9,
      ]);
      const expectedAddr = new Uint32Array([30, 13, 25, 0, 104, 44, 95, 110]);
      treeHashUpdate(HASH_FUNCTION.SHAKE_128, bdsState.treeHash[2], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[2]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should update tree hash, with SHAKE_256 hashing', () => {
      const height = 9;
      const k = 5;
      const w = 3;
      const n = 5;
      const bdsState = newBDSState(height, n, k);
      const skSeed = new Uint8Array([
        29, 82, 58, 111, 23, 19, 72, 43, 0, 30, 123, 110, 79, 57, 84, 58, 88, 27, 10, 119, 100, 3, 100, 123, 48, 72, 15,
        112, 17, 78, 39, 85, 4, 17, 40, 22,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        48, 17, 111, 65, 76, 55, 50, 93, 65, 95, 100, 41, 99, 120, 73, 18, 110, 81, 71, 8, 62, 45, 10, 47, 6, 33, 16,
        24, 96, 116, 57, 93, 57, 52, 22, 21, 83, 10, 42, 47, 16, 31, 103, 16, 107, 119, 113, 20, 40, 24, 42, 36, 90, 54,
        44, 119, 4, 21, 116, 34, 91, 116, 64,
      ]);
      const addr = new Uint32Array([112, 62, 16, 64, 4, 25, 123, 16]);
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = new Uint8Array([200, 169, 62, 57, 227]);
      const expectedSkSeed = new Uint8Array([
        29, 82, 58, 111, 23, 19, 72, 43, 0, 30, 123, 110, 79, 57, 84, 58, 88, 27, 10, 119, 100, 3, 100, 123, 48, 72, 15,
        112, 17, 78, 39, 85, 4, 17, 40, 22,
      ]);
      const expectedPubSeed = new Uint8Array([
        48, 17, 111, 65, 76, 55, 50, 93, 65, 95, 100, 41, 99, 120, 73, 18, 110, 81, 71, 8, 62, 45, 10, 47, 6, 33, 16,
        24, 96, 116, 57, 93, 57, 52, 22, 21, 83, 10, 42, 47, 16, 31, 103, 16, 107, 119, 113, 20, 40, 24, 42, 36, 90, 54,
        44, 119, 4, 21, 116, 34, 91, 116, 64,
      ]);
      const expectedAddr = new Uint32Array([112, 62, 16, 64, 4, 25, 123, 16]);
      treeHashUpdate(HASH_FUNCTION.SHAKE_256, bdsState.treeHash[3], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[3]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('treeHashMinHeightOnStack', () => {
    it('should update r with stackOffset[0] and modified values', () => {
      const height = 9;
      const k = 5;
      const w = 3;
      const n = 5;
      const state = newBDSState(height, n, k);
      const params = newXMSSParams(n, height, w, k);
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(9);
    });

    it('should update r with stackOffset[6] and modified values', () => {
      const height = 11;
      const k = 4;
      const w = 2;
      const n = 3;
      const params = newXMSSParams(n, height, w, k);
      const state = newBDSState(height, n, k);
      state.stackOffset = 6;
      state.treeHash[0].stackUsage = 4;
      state.stackLevels = new Uint8Array([33, 45, 2, 4, 77, 23, 2]);
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(2);
    });

    it('should update r with stackOffset[17] and modified values', () => {
      const height = 5;
      const k = 1;
      const w = 9;
      const n = 2;
      const params = newXMSSParams(n, height, w, k);
      const state = newBDSState(height, n, k);
      state.stackOffset = 17;
      state.treeHash[0].stackUsage = 12;
      state.stackLevels = new Uint8Array([
        66, 2, 5, 77, 8, 6, 99, 0, 1, 66, 2, 5, 77, 8, 6, 99, 0, 1, 66, 2, 5, 77, 8, 6, 99, 0, 1,
      ]);
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(0);
    });
  });

  describe('bdsTreeHashUpdate', () => {
    it('should update the tree hash, with SHA2_256 hashing', () => {
      const height = 5;
      const k = 1;
      const w = 9;
      const n = 1;
      const bdsState = newBDSState(height, n, k);
      const updates = 7;
      const skSeed = new Uint8Array([
        48, 3, 114, 49, 48, 108, 59, 28, 95, 70, 106, 69, 16, 59, 67, 96, 73, 25, 74, 107, 16, 68, 22, 77, 47, 22, 56,
        72, 19, 17, 64, 6, 48, 59, 80, 84, 54, 96, 47, 5, 30, 117, 22,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        98, 48, 44, 60, 17, 40, 99, 56, 68, 64, 41, 49, 66, 70, 92, 4, 92, 30, 92, 63, 105, 34, 15, 83, 120, 23, 24, 82,
        74, 122, 52, 70, 81, 9, 39, 47,
      ]);
      const addr = new Uint32Array([31, 6, 19, 87, 120, 41, 13, 62]);
      const expectedSkSeed = new Uint8Array([
        48, 3, 114, 49, 48, 108, 59, 28, 95, 70, 106, 69, 16, 59, 67, 96, 73, 25, 74, 107, 16, 68, 22, 77, 47, 22, 56,
        72, 19, 17, 64, 6, 48, 59, 80, 84, 54, 96, 47, 5, 30, 117, 22,
      ]);
      const expectedPubSeed = new Uint8Array([
        98, 48, 44, 60, 17, 40, 99, 56, 68, 64, 41, 49, 66, 70, 92, 4, 92, 30, 92, 63, 105, 34, 15, 83, 120, 23, 24, 82,
        74, 122, 52, 70, 81, 9, 39, 47,
      ]);
      const expectedAddr = new Uint32Array([31, 6, 19, 87, 120, 41, 13, 62]);
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHA2_256, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(3);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should update the tree hash, with SHAKE_128 hashing', () => {
      const height = 11;
      const k = 4;
      const w = 7;
      const n = 3;
      const bdsState = newBDSState(height, n, k);
      const updates = 9;
      const skSeed = new Uint8Array([
        19, 121, 122, 105, 79, 66, 63, 46, 7, 70, 81, 116, 68, 38, 99, 11, 1, 111, 113, 105, 3, 19, 1, 45, 114, 82, 21,
        92, 49, 34, 40, 40, 52, 96, 50, 119, 39,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        69, 86, 0, 98, 15, 38, 75, 103, 95, 8, 1, 107, 88, 71, 96, 116, 60, 30, 53, 79, 45, 41, 52, 59, 52, 75, 31, 39,
      ]);
      const addr = new Uint32Array([66, 37, 9, 40, 120, 12, 45, 75]);
      const expectedSkSeed = new Uint8Array([
        19, 121, 122, 105, 79, 66, 63, 46, 7, 70, 81, 116, 68, 38, 99, 11, 1, 111, 113, 105, 3, 19, 1, 45, 114, 82, 21,
        92, 49, 34, 40, 40, 52, 96, 50, 119, 39,
      ]);
      const expectedPubSeed = new Uint8Array([
        69, 86, 0, 98, 15, 38, 75, 103, 95, 8, 1, 107, 88, 71, 96, 116, 60, 30, 53, 79, 45, 41, 52, 59, 52, 75, 31, 39,
      ]);
      const expectedAddr = new Uint32Array([66, 37, 9, 40, 120, 12, 45, 75]);
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHAKE_128, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(2);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should update the tree hash, with SHAKE_256 hashing', () => {
      const height = 17;
      const k = 13;
      const w = 3;
      const n = 7;
      const bdsState = newBDSState(height, n, k);
      const updates = 17;
      const skSeed = new Uint8Array([
        54, 13, 56, 92, 0, 42, 95, 70, 71, 103, 60, 115, 79, 49, 18, 48, 60, 100, 106, 112,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        120, 51, 60, 88, 35, 43, 78, 70, 1, 55, 14, 93, 81, 81, 51, 66, 101, 25, 43, 14, 58, 30, 23, 120, 107, 37, 47,
        30, 93, 66, 28, 54, 80, 59, 66, 118, 81, 46, 50,
      ]);
      const addr = new Uint32Array([115, 41, 69, 102, 20, 38, 94, 33]);
      const expectedSkSeed = new Uint8Array([
        54, 13, 56, 92, 0, 42, 95, 70, 71, 103, 60, 115, 79, 49, 18, 48, 60, 100, 106, 112,
      ]);
      const expectedPubSeed = new Uint8Array([
        120, 51, 60, 88, 35, 43, 78, 70, 1, 55, 14, 93, 81, 81, 51, 66, 101, 25, 43, 14, 58, 30, 23, 120, 107, 37, 47,
        30, 93, 66, 28, 54, 80, 59, 66, 118, 81, 46, 50,
      ]);
      const expectedAddr = new Uint32Array([115, 41, 69, 102, 20, 38, 94, 33]);
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHAKE_256, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(13);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });
  });

  describe('bdsRound', () => {
    it('should run bdsRound, with SHA2_256 hashing', () => {
      const height = 19;
      const k = 7;
      const w = 13;
      const n = 17;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 5;
      const skSeed = new Uint8Array([
        70, 83, 15, 49, 57, 52, 66, 63, 65, 12, 40, 23, 101, 116, 113, 89, 12, 51, 52, 107, 5, 105, 100, 95, 97, 2, 99,
        100, 7, 26, 87,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        104, 21, 2, 55, 96, 74, 64, 10, 56, 15, 22, 117, 28, 73, 44, 84, 101, 54, 113, 6, 75, 69, 49, 28, 25, 113, 45,
      ]);
      const addr = new Uint32Array([90, 24, 2, 6, 90, 59, 13, 81]);
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.treeHash[0].nextIdx = 9;
      expectedBdsState.auth = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 42, 208, 202, 71, 56, 36, 188, 231, 251, 107, 154, 115,
        168, 101, 62, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      const expectedSkSeed = new Uint8Array([
        70, 83, 15, 49, 57, 52, 66, 63, 65, 12, 40, 23, 101, 116, 113, 89, 12, 51, 52, 107, 5, 105, 100, 95, 97, 2, 99,
        100, 7, 26, 87,
      ]);
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = new Uint8Array([
        104, 21, 2, 55, 96, 74, 64, 10, 56, 15, 22, 117, 28, 73, 44, 84, 101, 54, 113, 6, 75, 69, 49, 28, 25, 113, 45,
      ]);
      const expectedAddr = new Uint32Array([90, 24, 2, 6, 90, 59, 13, 81]);
      bdsRound(HASH_FUNCTION.SHA2_256, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should run bdsRound, with SHAKE_128 hashing', () => {
      const height = 8;
      const k = 8;
      const w = 19;
      const n = 3;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 13;
      const skSeed = new Uint8Array([
        99, 61, 110, 52, 106, 2, 60, 29, 32, 61, 24, 43, 111, 118, 40, 80, 20, 11, 87, 7, 28, 69, 118, 75, 62, 53, 106,
        116, 79, 18, 102, 93, 26, 83, 31, 1, 101, 20, 92, 77, 11, 6, 94, 96, 26, 71,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        100, 59, 118, 122, 23, 56, 39, 27, 37, 74, 104, 15, 117, 63, 119, 59, 82, 83, 84, 111, 13, 97, 41, 81, 13, 50,
        16, 53, 113, 101, 104, 25, 29, 23,
      ]);
      const addr = new Uint32Array([114, 21, 27, 15, 50, 21, 28, 7]);
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = new Uint8Array([
        0, 0, 0, 85, 31, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      const expectedSkSeed = new Uint8Array([
        99, 61, 110, 52, 106, 2, 60, 29, 32, 61, 24, 43, 111, 118, 40, 80, 20, 11, 87, 7, 28, 69, 118, 75, 62, 53, 106,
        116, 79, 18, 102, 93, 26, 83, 31, 1, 101, 20, 92, 77, 11, 6, 94, 96, 26, 71,
      ]);
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = new Uint8Array([
        100, 59, 118, 122, 23, 56, 39, 27, 37, 74, 104, 15, 117, 63, 119, 59, 82, 83, 84, 111, 13, 97, 41, 81, 13, 50,
        16, 53, 113, 101, 104, 25, 29, 23,
      ]);
      const expectedAddr = new Uint32Array([114, 21, 27, 15, 50, 21, 28, 7]);
      bdsRound(HASH_FUNCTION.SHAKE_128, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should run bdsRound, with SHAKE_256 hashing', () => {
      const height = 7;
      const k = 7;
      const w = 5;
      const n = 2;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 9;
      const skSeed = new Uint8Array([
        41, 85, 10, 57, 96, 43, 82, 123, 20, 60, 25, 5, 0, 15, 57, 69, 6, 27, 57, 43, 24, 43, 102, 100, 20, 14, 5, 64,
        31, 72, 120, 6, 8, 92, 95, 120, 33, 73, 85, 36, 57, 68, 94,
      ]);
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = new Uint8Array([
        88, 43, 72, 0, 117, 19, 84, 73, 52, 34, 20, 4, 24, 24, 50, 11, 119, 17, 39, 15, 66, 45, 81, 38, 71, 102,
      ]);
      const addr = new Uint32Array([86, 82, 23, 31, 36, 115, 37, 70]);
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = new Uint8Array([0, 0, 8, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const expectedSkSeed = new Uint8Array([
        41, 85, 10, 57, 96, 43, 82, 123, 20, 60, 25, 5, 0, 15, 57, 69, 6, 27, 57, 43, 24, 43, 102, 100, 20, 14, 5, 64,
        31, 72, 120, 6, 8, 92, 95, 120, 33, 73, 85, 36, 57, 68, 94,
      ]);
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = new Uint8Array([
        88, 43, 72, 0, 117, 19, 84, 73, 52, 34, 20, 4, 24, 24, 50, 11, 119, 17, 39, 15, 66, 45, 81, 38, 71, 102,
      ]);
      const expectedAddr = new Uint32Array([86, 82, 23, 31, 36, 115, 37, 70]);
      bdsRound(HASH_FUNCTION.SHAKE_256, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });
  });
});
