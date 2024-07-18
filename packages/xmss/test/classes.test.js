import { expect } from 'chai';
import { describe, it } from 'mocha';
import {
  newBDSState,
  newQRLDescriptor,
  newQRLDescriptorFromBytes,
  newQRLDescriptorFromExtendedPk,
  newQRLDescriptorFromExtendedSeed,
  newTreeHashInst,
  newWOTSParams,
  newXMSSParams,
} from '../src/classes.js';
import { COMMON, CONSTANTS, HASH_FUNCTION } from '../src/constants.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './utility/testUtility.js';

describe('Test cases for [classes]', () => {
  describe('newTreeHashInst', () => {
    it('should create a TreeHashInst instance', () => {
      const treeHashInst = newTreeHashInst(8);
      const expectedTreeHashNode = getUInt8ArrayFromHex('0000000000000000');

      expect(Object.getOwnPropertyNames(treeHashInst)).to.deep.equal([
        'h',
        'nextIdx',
        'stackUsage',
        'completed',
        'node',
      ]);
      expect(treeHashInst.completed).to.equal(0);
      expect(treeHashInst.h).to.equal(0);
      expect(treeHashInst.nextIdx).to.equal(0);
      expect(treeHashInst.node).to.deep.equal(expectedTreeHashNode);
      expect(treeHashInst.node.length).to.equal(8);
      expect(treeHashInst.stackUsage).to.equal(0);
    });

    it('should create a TreeHashInst instance with default n value 0', () => {
      const treeHashInst = newTreeHashInst();
      const expectedTreeHashNode = getUInt8ArrayFromHex('');

      expect(treeHashInst.node).to.deep.equal(expectedTreeHashNode);
      expect(treeHashInst.node.length).to.equal(0);
    });
  });

  describe('newBDSState', () => {
    it('should create a BDSState instance', () => {
      const height = 10;
      const n = 6;
      const k = 9;
      const bdsState = newBDSState(height, n, k);

      expect(Object.getOwnPropertyNames(bdsState)).to.deep.equal([
        'stackOffset',
        'stack',
        'stackLevels',
        'auth',
        'keep',
        'treeHash',
        'retain',
        'nextLeaf',
      ]);
      expect(bdsState.stackOffset).to.equal(0);
      expect(bdsState.stack.length).to.equal((height + 1) * n);
      expect(bdsState.stackLevels.length).to.equal(height + 1);
      expect(bdsState.auth.length).to.equal(height * n);
      expect(bdsState.keep.length).to.equal((height >> 1) * n);
      expect(bdsState.treeHash.length).to.equal(height - k);
      expect(bdsState.retain.length).to.equal(((1 << k) - k - 1) * n);
      expect(bdsState.nextLeaf).to.equal(0);
    });
  });

  describe('newWOTSParams', () => {
    it('should create a WOTSParams instance, with n[6] and w[6]', () => {
      const n = 6;
      const w = 6;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(24);
      expect(wotsParams.len2).to.equal(4);
      expect(wotsParams.len).to.equal(28);
      expect(wotsParams.n).to.equal(6);
      expect(wotsParams.w).to.equal(6);
      expect(wotsParams.logW).to.equal(2);
      expect(wotsParams.keySize).to.equal(168);
    });

    it('should create a WOTSParams instance, with n[32] and w[16]', () => {
      const n = 32;
      const w = 16;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(64);
      expect(wotsParams.len2).to.equal(3);
      expect(wotsParams.len).to.equal(67);
      expect(wotsParams.n).to.equal(32);
      expect(wotsParams.w).to.equal(16);
      expect(wotsParams.logW).to.equal(4);
      expect(wotsParams.keySize).to.equal(2144);
    });

    it('should create a WOTSParams instance, with n[8] and w[7]', () => {
      const n = 8;
      const w = 7;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(32);
      expect(wotsParams.len2).to.equal(4);
      expect(wotsParams.len).to.equal(36);
      expect(wotsParams.n).to.equal(8);
      expect(wotsParams.w).to.equal(7);
      expect(wotsParams.logW).to.equal(2);
      expect(wotsParams.keySize).to.equal(288);
    });

    it('should create a WOTSParams instance, with n[13] and w[16]', () => {
      const n = 13;
      const w = 16;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(26);
      expect(wotsParams.len2).to.equal(3);
      expect(wotsParams.len).to.equal(29);
      expect(wotsParams.n).to.equal(13);
      expect(wotsParams.w).to.equal(16);
      expect(wotsParams.logW).to.equal(4);
      expect(wotsParams.keySize).to.equal(377);
    });

    it('should create a WOTSParams instance, with n[7] and w[256]', () => {
      const n = 7;
      const w = 256;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(7);
      expect(wotsParams.len2).to.equal(2);
      expect(wotsParams.len).to.equal(9);
      expect(wotsParams.n).to.equal(7);
      expect(wotsParams.w).to.equal(256);
      expect(wotsParams.logW).to.equal(8);
      expect(wotsParams.keySize).to.equal(63);
    });
  });

  describe('newXMSSParams', () => {
    it('should create a WOTSParams instance', () => {
      const n = 2;
      const h = 4;
      const w = 6;
      const k = 8;
      const xmssParams = newXMSSParams(n, h, w, k);

      expect(Object.getOwnPropertyNames(xmssParams)).to.deep.equal(['wotsParams', 'n', 'h', 'k']);
      expect(xmssParams.wotsParams).to.deep.equal(newWOTSParams(n, w));
      expect(xmssParams.n).to.equal(n);
      expect(xmssParams.h).to.equal(h);
      expect(xmssParams.k).to.equal(k);
    });
  });

  describe('newQRLDescriptor', () => {
    it('should create a QRLDescriptor instance', () => {
      const [height] = getUInt8ArrayFromHex('05');
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const [signatureType] = getUInt32ArrayFromHex('00000004');
      const [addrFormatType] = getUInt32ArrayFromHex('00000041');
      const qrlDescriptor = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
      expect(qrlDescriptor.hashFunction).to.equal(1);
      expect(qrlDescriptor.signatureType).to.equal(signatureType);
      expect(qrlDescriptor.height).to.equal(height);
      expect(qrlDescriptor.addrFormatType).to.equal(addrFormatType);
    });
  });

  describe('newQRLDescriptorFromBytes', () => {
    it('should create a QRLDescriptor instance', () => {
      const descriptorBytes = getUInt8ArrayFromHex('030609');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of descriptionBytes array is not 3', () => {
      const descriptorBytes = getUInt8ArrayFromHex('2d210703064d');

      expect(() => newQRLDescriptorFromBytes(descriptorBytes)).to.throw('Descriptor size should be 3 bytes');
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[310622]', () => {
      const descriptorBytes = getUInt8ArrayFromHex('310622');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(1);
      expect(qrlDescriptor.signatureType).to.equal(3);
      expect(qrlDescriptor.height).to.equal(12);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[0001fe]', () => {
      const descriptorBytes = getUInt8ArrayFromHex('0001fe');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(0);
      expect(qrlDescriptor.signatureType).to.equal(0);
      expect(qrlDescriptor.height).to.equal(2);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[dc006f]', () => {
      const descriptorBytes = getUInt8ArrayFromHex('dc006f');
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(12);
      expect(qrlDescriptor.signatureType).to.equal(13);
      expect(qrlDescriptor.height).to.equal(0);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });
  });

  describe('newQRLDescriptorFromExtendedSeed', () => {
    it('should create a QRLDescriptor instance', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '09040609010c02090c04060d03020c060c040205040c080b0d0f0b00070009040202060808030e030806020600090307060e0e'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of extendedSeeds array is not EXTENDED_SEED_SIZE', () => {
      const extendedSeeds = getUInt8ArrayFromHex('04');

      expect(() => newQRLDescriptorFromExtendedSeed(extendedSeeds)).to.throw(
        `extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`
      );
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[0904...]', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '09040609010c02090c04060d03020c060c040205040c080b0d0f0b00070009040202060808030e030806020600090307060e0e'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(9);
      expect(qrlDescriptor.signatureType).to.equal(0);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[5ca4...]', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '5ca44e1b1494e62e5c71412296cb03641d0260459481f3b68ab5dbdf58d3caaa50929bef44179a8a17bf3f02a41d0e84cd3d03'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(12);
      expect(qrlDescriptor.signatureType).to.equal(5);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(10);
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[8d09...]', () => {
      const extendedSeeds = getUInt8ArrayFromHex(
        '8d09b9667bb190d5973487600a6a2e74171a973281b777bc7fa3c7abcbcb775961f1430daa629b6ba42892cc04ece0d24300a1'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(13);
      expect(qrlDescriptor.signatureType).to.equal(8);
      expect(qrlDescriptor.height).to.equal(18);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });
  });

  describe('newQRLDescriptorFromExtendedPk', () => {
    it('should create a QRLDescriptor instance', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '43053fefbec25a3f74f3f09ad654d94e7da64b591e0ed100908cd343dda572489127510959df03faa33fae8cbca444f3732b5b17c18633b9e3fdb26e56f07059342156'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of extendedPk array is not EXTENDED_PK_SIZE', () => {
      const extendedPk = getUInt8ArrayFromHex('3857');

      expect(() => newQRLDescriptorFromExtendedPk(extendedPk)).to.throw(
        `extendedPk should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`
      );
    });

    it('should create a QRLDescriptor instance, with extendedPk[4305...]', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '43053fefbec25a3f74f3f09ad654d94e7da64b591e0ed100908cd343dda572489127510959df03faa33fae8cbca444f3732b5b17c18633b9e3fdb26e56f07059342156'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(3);
      expect(qrlDescriptor.signatureType).to.equal(4);
      expect(qrlDescriptor.height).to.equal(10);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with extendedPk[6d14...]', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '6d14dadec8746dd12d54f2ee01d7127c4dde8eb7dae07b6d6998a480741e9cf6db1496facf78161485b3355782ccb7ea6d5e37bbf22bb3130a51809714f5cfd812eb01'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(13);
      expect(qrlDescriptor.signatureType).to.equal(6);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(1);
    });

    it('should create a QRLDescriptor instance, with extendedPk[6619...]', () => {
      const extendedPk = getUInt8ArrayFromHex(
        '6619995e50d6f161a2b69063d626e7e377bcb2ca1638ab7d6f00d398816459846938345670935c7de8342488f7848c6120d8d941f7ec686b033917ac8866494e582fd4'
      );
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(6);
      expect(qrlDescriptor.signatureType).to.equal(6);
      expect(qrlDescriptor.height).to.equal(18);
      expect(qrlDescriptor.addrFormatType).to.equal(1);
    });
  });
});
