import { expect } from 'chai';
import { describe, it } from 'mocha';
import { ENDIAN } from '../src/constants.js';
import {
  addrToByte,
  binToMnemonic,
  seedBinToMnemonic,
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

    it('should return the SHAKE128 hashed Uint8Array with message[96] and out[56]', () => {
      const message = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 209, 102, 32,
        21, 94, 88, 20, 52, 117, 63, 238, 1, 233, 228, 206, 89, 176, 229, 139, 81, 148, 219, 32, 239, 174, 49, 100, 104,
        109, 249, 117, 17, 1, 206, 234, 165, 63, 68, 246, 221, 76, 89, 52, 141, 135, 56, 28, 54, 221, 83, 115, 243, 7,
        122, 128, 76, 50, 18, 70, 252, 248, 194, 207, 190,
      ]);
      let out = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      out = shake128(out, message);
      const expectedSha256Out = new Uint8Array([
        110, 44, 82, 245, 12, 128, 228, 117, 8, 136, 75, 54, 4, 254, 183, 211, 170, 24, 84, 230, 63, 60, 157, 93, 7, 21,
        66, 112, 5, 54, 53, 126, 204, 34, 218, 19, 6, 183, 253, 154, 106, 95, 140, 151, 249, 223, 241, 27, 13, 82, 130,
        161, 250, 46, 108, 123,
      ]);

      expect(out).to.deep.equal(expectedSha256Out);
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

    it('should return the SHAKE256 hashed Uint8Array with message[96] and out[56]', () => {
      const message = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 171, 161, 59,
        82, 31, 217, 77, 241, 94, 49, 155, 39, 214, 118, 80, 133, 24, 53, 93, 65, 142, 242, 166, 117, 98, 203, 68, 189,
        131, 104, 203, 128, 50, 188, 53, 181, 77, 74, 189, 204, 135, 129, 255, 175, 206, 158, 6, 215, 80, 216, 7, 144,
        179, 253, 60, 159, 212, 33, 47, 136, 94, 14, 206, 127,
      ]);
      let out = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      out = shake256(out, message);
      const expectedSha256Out = new Uint8Array([
        189, 180, 53, 200, 107, 40, 146, 72, 115, 217, 101, 223, 168, 123, 61, 89, 162, 231, 238, 93, 89, 78, 237, 252,
        39, 110, 47, 153, 249, 149, 252, 171, 19, 117, 45, 125, 99, 81, 150, 29, 209, 53, 22, 107, 1, 63, 215, 225, 150,
        60, 36, 166, 81, 101, 252, 30,
      ]);

      expect(out).to.deep.equal(expectedSha256Out);
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

    it('should return the SHA256 hashed Uint8Array with message[96] and out[56]', () => {
      const message = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 207, 210, 131,
        49, 77, 71, 254, 199, 74, 126, 55, 160, 149, 168, 40, 122, 175, 166, 2, 131, 91, 171, 241, 142, 164, 96, 194,
        33, 28, 47, 233, 120, 166, 253, 105, 226, 1, 195, 24, 118, 180, 145, 114, 141, 9, 8, 226, 90, 35, 172, 151, 195,
        18, 5, 217, 143, 208, 121, 110, 148, 76, 234, 16, 249,
      ]);
      let out = new Uint8Array([
        1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 2, 2, 7, 3, 1, 3, 4, 4, 3, 3, 5, 1, 2, 7,
        2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
      ]);
      out = sha256(out, message);
      const expectedSha256Out = new Uint8Array([
        83, 91, 26, 111, 69, 189, 212, 121, 108, 125, 181, 168, 17, 241, 17, 230, 56, 127, 47, 57, 163, 111, 24, 196,
        47, 222, 103, 251, 212, 239, 249, 202, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3, 3, 5, 1, 2, 7, 2, 7, 3,
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

  describe('binToMnemonic', () => {
    it('should generate mnemonic from binary, with input length [3]', () => {
      const input = new Uint8Array([56, 255, 0]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic = 'deed utmost';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [12]', () => {
      const input = new Uint8Array([142, 56, 203, 87, 129, 45, 230, 178, 66, 34, 112, 255]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic = 'modern mind friar bath tomb carbon calf bad';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [30]', () => {
      const input = new Uint8Array([
        72, 189, 33, 255, 128, 47, 163, 212, 54, 99, 238, 67, 140, 84, 210, 3, 176, 122, 91, 200, 44, 155, 219, 60, 131,
        17, 243, 101, 85, 196,
      ]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'essex spin zero adopt pill early hail throng mile fast afloat amen gene louvre orphan regret lower build harry genus';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [300]', () => {
      const input = new Uint8Array([
        124, 83, 216, 11, 99, 205, 36, 148, 67, 255, 192, 81, 48, 135, 179, 6, 229, 142, 200, 74, 91, 53, 117, 250, 168,
        32, 201, 109, 207, 215, 187, 128, 163, 93, 66, 38, 221, 190, 44, 174, 13, 57, 182, 243, 120, 147, 95, 65, 175,
        234, 39, 108, 27, 141, 77, 210, 5, 199, 87, 225, 106, 240, 33, 170, 54, 131, 14, 194, 69, 137, 150, 102, 206,
        211, 84, 189, 121, 251, 162, 49, 185, 7, 56, 230, 103, 218, 112, 183, 42, 159, 76, 20, 248, 155, 37, 219, 164,
        30, 228, 96, 204, 67, 233, 123, 198, 10, 134, 71, 192, 111, 27, 245, 160, 87, 200, 118, 175, 55, 143, 78, 217,
        104, 252, 31, 138, 209, 115, 241, 66, 188, 43, 151, 176, 98, 169, 56, 231, 13, 105, 190, 32, 218, 130, 86, 255,
        70, 149, 193, 9, 237, 106, 185, 45, 222, 88, 35, 209, 171, 20, 240, 57, 153, 91, 242, 173, 65, 203, 110, 139,
        217, 76, 179, 54, 132, 226, 7, 180, 97, 202, 48, 146, 115, 251, 80, 195, 25, 127, 68, 214, 158, 41, 179, 104,
        253, 92, 147, 35, 162, 187, 114, 21, 236, 59, 168, 99, 205, 83, 212, 50, 119, 144, 73, 250, 138, 63, 197, 84,
        176, 29, 240, 110, 172, 41, 215, 96, 186, 28, 153, 203, 51, 145, 220, 38, 201, 126, 62, 188, 116, 225, 74, 157,
        139, 30, 243, 61, 134, 93, 204, 51, 229, 87, 175, 12, 247, 109, 194, 36, 221, 49, 190, 102, 231, 78, 146, 198,
        86, 179, 40, 215, 125, 163, 70, 200, 28, 156, 134, 77, 238, 58, 149, 207, 65, 186, 103, 249, 113, 131, 169, 32,
        223, 50, 210, 74, 160, 137, 6, 193, 81, 174, 108, 250, 126, 95, 23, 212, 53, 161, 140, 7, 218, 111, 47, 152,
        237, 82, 206, 37, 189, 13, 242, 124, 68, 201, 159, 49, 171, 90, 180, 33, 231, 144, 117, 38, 222, 59, 205, 74,
        145, 188, 103, 250, 48, 163, 21, 243, 97, 137, 129, 2, 176, 35, 198, 120, 83, 219, 42, 204, 57, 134, 185, 70,
        213, 14, 172, 141, 31, 192, 98, 157, 39, 246, 65, 220, 106, 207, 13, 150, 93, 184, 47, 242, 75, 169, 12, 197,
        52, 226, 124, 111, 230,
      ]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'ledge dispel arrow dingus carnal eddy zipper airy cosmic layer aloof fully signal plate curse grab pony assist icon wreck rudder arcane glance cakile tace thesis quay square rhine david naples virus raid petty hound rival feat burma shrine lewis hold active price held await career meet havoc sold curl saga paste peru bovine altar module hedge poem rhyme prefer fairly fierce oracle glib pin unkind great shabby treaty rust area hammer scent venom walk alert silken hold david volley stunt mortal bull purely jest beet runway robust range clammy deduce insert hidden than sullen casual zaire hero screen parcel hoard mystic talent lose spend rave vacuum oily genius clasp duel rhexia middle nephew refer helium than layman grit picket mutton draft firm cousin limp fate pair orange herb steel namely demo ruby buyer turf rosa had static stair chart mostly past mental woods follow acre valet trot cider just roll sit sleeve deeply swear human liar tundra joy beige pack real view street glide sent tight lawn ate kernel seed feat cover tokyo topaz trauma shiver holy chilly knack pier hull brave silk fed those nimble virus root linger invade depart bust vienna spinus prefix mean hound flank tonal win tip blast earl pencil school suite victim ocean state socket geneva auntie check eerily omega cove resign relief brush motion flew take sacred exit bowl hefty picket picnic gosh grim nylon adjust actual shoe magnet super punk defy hopple energy first pump spiky scent cider cheer haiti sweep puppy auburn hasty rinse your facial mourn sharp feel left year';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('seedBinToMnemonic', () => {
    it('should generate mnemonic from binary, with input[216, 6...]', () => {
      const input = new Uint8Array([
        216, 6, 203, 205, 184, 41, 181, 190, 26, 53, 67, 17, 186, 227, 248, 206, 244, 173, 206, 15, 16, 228, 122, 34,
        104, 172, 200, 0, 116, 188, 137, 217, 114, 232, 107, 173, 171, 82, 207, 229, 248, 145, 224, 100, 4, 21, 72, 217,
      ]);
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'strap humble snug loudly resin tera curl could rotten dower solely expect social vast thug person hemp smart abode factor melt note toxin rotor proper clutch tip meant tehran dread bend mite';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[68, 138...]', () => {
      const input = new Uint8Array([
        68, 138, 136, 146, 133, 23, 200, 18, 219, 14, 98, 146, 98, 179, 251, 97, 15, 249, 174, 147, 60, 182, 163, 39,
        230, 218, 162, 2, 169, 78, 175, 117, 182, 24, 52, 236, 230, 117, 157, 5, 84, 195, 131, 47, 32, 207, 109, 5,
      ]);
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'edit popery mutual flair sight coffee avail choose guess draft greek zigzag quilt crop revive crater tone pretty adhere nest radar gave blink ferry told gag albeit falcon lowest verbal son soul';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[10, 200...]', () => {
      const input = new Uint8Array([
        10, 200, 187, 235, 252, 23, 230, 48, 12, 74, 80, 36, 231, 30, 164, 75, 106, 200, 121, 20, 106, 118, 49, 49, 70,
        23, 184, 221, 2, 224, 187, 1, 94, 246, 101, 107, 78, 82, 168, 133, 213, 115, 245, 125, 104, 68, 222, 84,
      ]);
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'arm midas tunic seam toast abra exempt acute tool tried eyed pump lady enamel karate bay embark leaf sword coke rough bestow warp frail fell claim male freer wait stiff effect tiger';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('extendedSeedBinToMnemonic', () => {
    it('should generate mnemonic from binary, with input[51, 195...]', () => {
      const input = new Uint8Array([
        51, 195, 194, 249, 122, 77, 150, 81, 126, 61, 6, 195, 120, 122, 92, 220, 102, 171, 77, 185, 63, 63, 123, 88,
        133, 139, 76, 27, 107, 26, 54, 145, 143, 233, 58, 105, 186, 177, 211, 191, 27, 133, 142, 84, 54, 168, 205, 84,
        110, 92, 203,
      ]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'crop diary wholly pivot noisy blaze dire house koran play sweep hoard fauna near dove resent main renal bound react dallas blunt travel plump rosy brew satin ripen modify early port statue ignore smell';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[61, 200...]', () => {
      const input = new Uint8Array([
        61, 200, 24, 79, 224, 24, 191, 53, 140, 13, 84, 128, 181, 66, 20, 162, 205, 92, 206, 89, 216, 247, 97, 85, 62,
        64, 52, 121, 72, 204, 87, 64, 78, 176, 12, 12, 80, 162, 154, 217, 154, 34, 13, 102, 3, 35, 134, 102, 242, 211,
        141,
      ]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'divine lone file ache saturn fulfil attach equip repine buy photo steel sodium pack weary bended dole aerial lake mine freeze aim rain scotch finish chrome submit person attain grass cane havoc vicar decree';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[155, 172...]', () => {
      const input = new Uint8Array([
        155, 172, 153, 159, 209, 11, 18, 15, 133, 152, 44, 238, 224, 226, 187, 174, 21, 25, 166, 9, 238, 29, 201, 223,
        125, 161, 208, 243, 184, 198, 189, 89, 10, 215, 230, 235, 54, 32, 146, 204, 242, 217, 244, 206, 15, 120, 174,
        119, 202, 127, 149,
      ]);
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'orient sit pastor ballad barrel what oak sole tenant climb quebec flame plead pardon brink paid let bred viola milk safer mould strait import dad anti smite cocoa voice tend kuwait torch slab who';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });
});
