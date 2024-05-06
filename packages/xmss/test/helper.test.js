import { expect } from 'chai';
import { describe, it } from 'mocha';
import { ENDIAN } from '../src/constants.js';
import {
  addrToByte,
  setChainAddr,
  setHashAddr,
  setKeyAndMask,
  setLTreeAddr,
  setOTSAddr,
  setTreeHeight,
  setTreeIndex,
  setType,
  sha256,
  shake128,
  shake256,
} from '../src/helper.js';

describe('helper', () => {
  describe('shake128', () => {
    it('should return the SHAKE128 hash of type Uint8Array', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      out = shake128(out, message);

      expect(out).to.be.an.instanceOf(Uint8Array);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[12] and out[15]', () => {
      const message = new Uint8Array(12);
      message[3] = 6;
      message[9] = 8;
      let out = new Uint8Array(15);
      out[0] = 1;
      out[7] = 2;
      const expectedShake128Out = new Uint8Array([
        114, 204, 87, 130, 216, 192, 144, 227, 210, 37, 113, 55, 15, 232, 92,
      ]);
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[12] and out[6]', () => {
      const message = new Uint8Array(12);
      message[1] = 3;
      message[11] = 9;
      let out = new Uint8Array(6);
      out[0] = 7;
      out[3] = 12;
      const expectedShake128Out = new Uint8Array([62, 198, 17, 144, 145, 4]);
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[30] and out[42]', () => {
      const message = new Uint8Array(30);
      message[13] = 17;
      let out = new Uint8Array(42);
      out[32] = 1;
      out[11] = 6;
      const expectedShake128Out = new Uint8Array([
        53, 149, 85, 96, 84, 172, 177, 150, 215, 170, 163, 243, 108, 114, 210, 129, 126, 76, 178, 134, 1, 11, 80, 18,
        17, 152, 118, 41, 67, 52, 132, 243, 224, 66, 152, 246, 206, 195, 167, 50, 120, 85,
      ]);
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });
  });

  describe('shake256', () => {
    it('should return the SHAKE256 hash of type Uint8Array', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      out = shake256(out, message);

      expect(out).to.be.an.instanceOf(Uint8Array);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[48] and out[18]', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      const expectedShake256Out = new Uint8Array([
        237, 163, 19, 201, 85, 145, 160, 35, 165, 179, 127, 54, 28, 7, 165, 117, 58, 146,
      ]);
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[12] and out[6]', () => {
      const message = new Uint8Array(12);
      message[0] = 5;
      let out = new Uint8Array(6);
      out[0] = 3;
      const expectedShake256Out = new Uint8Array([119, 94, 102, 126, 219, 180]);
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[54] and out[15]', () => {
      const message = new Uint8Array(54);
      message[5] = 7;
      let out = new Uint8Array(15);
      out[3] = 12;
      const expectedShake256Out = new Uint8Array([
        206, 80, 114, 99, 195, 185, 167, 206, 248, 101, 163, 95, 103, 29, 151,
      ]);
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });
  });

  describe('sha256', () => {
    it('should return the SHA256 hash of type Uint8Array', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      out = sha256(out, message);

      expect(out).to.be.an.instanceOf(Uint8Array);
    });

    it('should return the SHA256 hashed Uint8Array with message[23] and out[16]', () => {
      const message = new Uint8Array(23);
      message[13] = 17;
      let out = new Uint8Array(16);
      out[7] = 8;
      out[11] = 6;
      out = sha256(out, message);
      const expectedSha256Out = new Uint8Array([
        148, 78, 77, 24, 183, 173, 216, 129, 205, 169, 72, 25, 52, 232, 41, 62,
      ]);

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[30] and out[30]', () => {
      const message = new Uint8Array(30);
      message[1] = 8;
      message[8] = 1;
      let out = new Uint8Array(30);
      out[29] = 32;
      out[8] = 4;
      out = sha256(out, message);
      const expectedSha256Out = new Uint8Array([
        89, 85, 100, 137, 196, 189, 197, 66, 195, 25, 235, 18, 54, 115, 73, 58, 190, 192, 212, 205, 37, 71, 108, 182,
        76, 6, 209, 97, 164, 127,
      ]);

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[4] and out[18]', () => {
      const message = new Uint8Array(4);
      message[1] = 6;
      message[2] = 4;
      message[3] = 2;
      let out = new Uint8Array(18);
      out[16] = 3;
      out[8] = 17;
      out[4] = 13;
      out = sha256(out, message);
      const expectedSha256Out = new Uint8Array([
        38, 238, 25, 172, 42, 38, 39, 85, 42, 218, 209, 83, 39, 254, 5, 44, 3, 96,
      ]);

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[96] and out[32]', () => {
      const message = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 5, 3, 1, 3,
        2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 2, 7, 3, 4, 5, 7, 8, 4, 5, 3, 1, 3, 2, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0,
        0, 2, 0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0,
      ]);
      let out = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      out = sha256(out, message);
      const expectedSha256Out = new Uint8Array([
        207, 210, 131, 49, 77, 71, 254, 199, 74, 126, 55, 160, 149, 168, 40, 122, 175, 166, 2, 131, 91, 171, 241, 142,
        164, 96, 194, 33, 28, 47, 233, 120,
      ]);

      expect(out).to.deep.equal(expectedSha256Out);
    });
  });

  describe('setType', () => {
    it('should set the type from index 3 till 7, with typeValue 1', () => {
      const addr = new Uint32Array([9, 9, 2, 3, 9, 1, 0, 5]);
      const typeValue = new Uint32Array([1])[0];
      setType(addr, typeValue);
      const expectedAddr = new Uint32Array([9, 9, 2, 1, 0, 0, 0, 0]);

      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should set the type from index 3 till 7, with typeValue 2', () => {
      const addr = new Uint32Array([2, 3, 5, 7, 4, 9, 1, 0]);
      const typeValue = new Uint32Array([2])[0];
      setType(addr, typeValue);
      const expectedAddr = new Uint32Array([2, 3, 5, 2, 0, 0, 0, 0]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setLTreeAddr', () => {
    it('should set the lTree at index 4', () => {
      const addr = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
      const lTree = new Uint32Array([20])[0];
      setLTreeAddr(addr, lTree);
      const expectedAddr = new Uint32Array([0, 1, 2, 3, 20, 5, 6, 7, 8]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setOTSAddr', () => {
    it('should set the ots at index 4', () => {
      const addr = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
      const ots = new Uint32Array([20])[0];
      setOTSAddr(addr, ots);
      const expectedAddr = new Uint32Array([0, 1, 2, 3, 20, 5, 6, 7, 8]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setChainAddr', () => {
    it('should set the chain at index 5', () => {
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const chain = new Uint32Array([16])[0];
      setChainAddr(addr, chain);
      const expectedAddr = new Uint32Array([1, 2, 3, 4, 5, 16, 7, 8]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setHashAddr', () => {
    it('should set the hash at index 6', () => {
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const hash = new Uint32Array([22])[0];
      setHashAddr(addr, hash);
      const expectedAddr = new Uint32Array([1, 2, 3, 4, 5, 6, 22, 8]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setKeyAndMask', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const keyAndMask = new Uint32Array([17])[0];
      setKeyAndMask(addr, keyAndMask);
      const expectedAddr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 17]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setTreeHeight', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
      const treeHeight = new Uint32Array([20])[0];
      setTreeHeight(addr, treeHeight);
      const expectedAddr = new Uint32Array([0, 1, 2, 3, 4, 20, 6, 7, 8]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setTreeIndex', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
      const treeIndex = new Uint32Array([18])[0];
      setTreeIndex(addr, treeIndex);
      const expectedAddr = new Uint32Array([0, 1, 2, 3, 4, 5, 18, 7, 8]);

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('addrToByte', () => {
    it('should add addr to bytes in case of little endian', () => {
      const getEndianFunc = () => ENDIAN.LITTLE;
      const bytes = new Uint8Array(32);
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = new Uint8Array([
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8,
      ]);

      expect(bytes).to.deep.equal(expectedUint8Array);
    });

    it('should add addr to bytes in case of big endian', () => {
      const getEndianFunc = () => ENDIAN.BIG;
      const bytes = new Uint8Array(32);
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = new Uint8Array([
        1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0,
      ]);

      expect(bytes).to.deep.equal(expectedUint8Array);
    });
  });
});
