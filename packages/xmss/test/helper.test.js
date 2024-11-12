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
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './utility/testUtility.js';

describe('Test cases for [helper]', () => {
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
      const expectedShake128Out = getUInt8ArrayFromHex('72cc5782d8c090e3d22571370fe85c');
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
      const expectedShake128Out = getUInt8ArrayFromHex('3ec611909104');
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[30] and out[42]', () => {
      const message = new Uint8Array(30);
      message[13] = 17;
      let out = new Uint8Array(42);
      out[32] = 1;
      out[11] = 6;
      const expectedShake128Out = getUInt8ArrayFromHex(
        '3595556054acb196d7aaa3f36c72d2817e4cb286010b501211987629433484f3e04298f6cec3a7327855'
      );
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[00000...] and out[0103...]', () => {
      const message = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000000000000000000000000000000000d16620155e581434753fee01e9e4ce59b0e58b5194db20efae3164686df9751101ceeaa53f44f6dd4c59348d87381c36dd5373f3077a804c321246fcf8c2cfbe'
      );
      let out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      out = shake128(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        '6e2c52f50c80e47508884b3604feb7d3aa1854e63f3c9d5d071542700536357ecc22da1306b7fd9a6a5f8c97f9dff11b0d5282a1fa2e6c7b'
      );

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
      const expectedShake256Out = getUInt8ArrayFromHex('eda313c95591a023a5b37f361c07a5753a92');
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[12] and out[6]', () => {
      const message = new Uint8Array(12);
      message[0] = 5;
      let out = new Uint8Array(6);
      out[0] = 3;
      const expectedShake256Out = getUInt8ArrayFromHex('775e667edbb4');
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[54] and out[15]', () => {
      const message = new Uint8Array(54);
      message[5] = 7;
      let out = new Uint8Array(15);
      out[3] = 12;
      const expectedShake256Out = getUInt8ArrayFromHex('ce507263c3b9a7cef865a35f671d97');
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[96] and out[56]', () => {
      const message = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000000000000000000000000000000000aba13b521fd94df15e319b27d676508518355d418ef2a67562cb44bd8368cb8032bc35b54d4abdcc8781ffafce9e06d750d80790b3fd3c9fd4212f885e0ece7f'
      );
      let out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      out = shake256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        'bdb435c86b28924873d965dfa87b3d59a2e7ee5d594eedfc276e2f99f995fcab13752d7d6351961dd135166b013fd7e1963c24a65165fc1e'
      );

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
      const expectedSha256Out = getUInt8ArrayFromHex('944e4d18b7add881cda9481934e8293e');

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
      const expectedSha256Out = getUInt8ArrayFromHex('59556489c4bdc542c319eb123673493abec0d4cd25476cb64c06d161a47f');

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
      const expectedSha256Out = getUInt8ArrayFromHex('26ee19ac2a2627552adad15327fe052c0360');

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[0000...] and out[0000...]', () => {
      const message = getUInt8ArrayFromHex(
        '000000000000000000000000000000000000000000000000000000000000000304050301030202070304050708040503010302020703040507080405030103020000000400000003000000020000000200000007000000030000000200000000'
      );
      let out = getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000');
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        'cfd283314d47fec74a7e37a095a8287aafa602835babf18ea460c2211c2fe978'
      );

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[0000...] and out[0103...]', () => {
      const message = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000000000000000000000000000000000cfd283314d47fec74a7e37a095a8287aafa602835babf18ea460c2211c2fe978a6fd69e201c31876b491728d0908e25a23ac97c31205d98fd0796e944cea10f9'
      );
      let out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        '535b1a6f45bdd4796c7db5a811f111e6387f2f39a36f18c42fde67fbd4eff9ca030501020702070303050102070207030305010207020703'
      );

      expect(out).to.deep.equal(expectedSha256Out);
    });
  });

  describe('setType', () => {
    it('should set the type from index 3 till 7, with typeValue 1', () => {
      const addr = getUInt32ArrayFromHex('0000000900000009000000020000000300000009000000010000000000000005');
      const typeValue = getUInt32ArrayFromHex('00000001')[0];
      setType(addr, typeValue);
      const expectedAddr = getUInt32ArrayFromHex('0000000900000009000000020000000100000000000000000000000000000000');

      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should set the type from index 3 till 7, with typeValue 2', () => {
      const addr = getUInt32ArrayFromHex('0000000200000003000000050000000700000004000000090000000100000000');
      const typeValue = getUInt32ArrayFromHex('00000002')[0];
      setType(addr, typeValue);
      const expectedAddr = getUInt32ArrayFromHex('0000000200000003000000050000000200000000000000000000000000000000');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setLTreeAddr', () => {
    it('should set the lTree at index 4', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const lTree = getUInt32ArrayFromHex('00000014')[0];
      setLTreeAddr(addr, lTree);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000001400000005000000060000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setOTSAddr', () => {
    it('should set the ots at index 4', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const ots = getUInt32ArrayFromHex('00000014')[0];
      setOTSAddr(addr, ots);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000001400000005000000060000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setChainAddr', () => {
    it('should set the chain at index 5', () => {
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      const chain = getUInt32ArrayFromHex('00000010')[0];
      setChainAddr(addr, chain);
      const expectedAddr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000100000000700000008');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setHashAddr', () => {
    it('should set the hash at index 6', () => {
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      const hash = getUInt32ArrayFromHex('00000016')[0];
      setHashAddr(addr, hash);
      const expectedAddr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000001600000008');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setKeyAndMask', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      const keyAndMask = getUInt32ArrayFromHex('00000011')[0];
      setKeyAndMask(addr, keyAndMask);
      const expectedAddr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000011');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setTreeHeight', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const treeHeight = getUInt32ArrayFromHex('00000014')[0];
      setTreeHeight(addr, treeHeight);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000000400000014000000060000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setTreeIndex', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const treeIndex = getUInt32ArrayFromHex('00000012')[0];
      setTreeIndex(addr, treeIndex);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000000400000005000000120000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('addrToByte', () => {
    it('should add addr to bytes in case of little endian', () => {
      const getEndianFunc = () => ENDIAN.LITTLE;
      const bytes = new Uint8Array(32);
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = getUInt8ArrayFromHex(
        '0000000100000002000000030000000400000005000000060000000700000008'
      );

      expect(bytes).to.deep.equal(expectedUint8Array);
    });

    it('should add addr to bytes in case of big endian', () => {
      const getEndianFunc = () => ENDIAN.BIG;
      const bytes = new Uint8Array(32);
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = getUInt8ArrayFromHex(
        '0100000002000000030000000400000005000000060000000700000008000000'
      );

      expect(bytes).to.deep.equal(expectedUint8Array);
    });
  });
});
