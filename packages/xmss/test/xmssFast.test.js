import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import {
  XMSSFastGenKeyPair,
  expandSeed,
  genChain,
  getSeed,
  hashF,
  lTree,
  treeHashSetup,
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

  xdescribe('TODO: genLeafWOTS', () => {
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
