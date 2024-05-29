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

describe('Test cases for [classes]', () => {
  describe('newTreeHashInst', () => {
    it('should create a TreeHashInst instance', () => {
      const treeHashInst = newTreeHashInst(8);

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
      expect(treeHashInst.node).to.deep.equal(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]));
      expect(treeHashInst.node.length).to.equal(8);
      expect(treeHashInst.stackUsage).to.equal(0);
    });

    it('should create a TreeHashInst instance with default n value 0', () => {
      const treeHashInst = newTreeHashInst();

      expect(treeHashInst.node).to.deep.equal(new Uint8Array([]));
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
      const [height] = new Uint8Array([5]);
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const [signatureType] = new Uint32Array([34]);
      const [addrFormatType] = new Uint32Array([65]);
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
      const descriptorBytes = new Uint8Array([3, 6, 9]);
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of descriptionBytes array is not 3', () => {
      const descriptorBytes = new Uint8Array([45, 33, 7, 3, 6, 77]);

      expect(() => newQRLDescriptorFromBytes(descriptorBytes)).to.throw('Descriptor size should be 3 bytes');
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[49, 6, 34]', () => {
      const descriptorBytes = new Uint8Array([49, 6, 34]);
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(1);
      expect(qrlDescriptor.signatureType).to.equal(3);
      expect(qrlDescriptor.height).to.equal(12);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[0, 1, 254]', () => {
      const descriptorBytes = new Uint8Array([0, 1, 254]);
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(0);
      expect(qrlDescriptor.signatureType).to.equal(0);
      expect(qrlDescriptor.height).to.equal(2);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with descriptorBytes[220, 0, 111]', () => {
      const descriptorBytes = new Uint8Array([220, 0, 111]);
      const qrlDescriptor = newQRLDescriptorFromBytes(descriptorBytes);

      expect(qrlDescriptor.hashFunction).to.equal(12);
      expect(qrlDescriptor.signatureType).to.equal(13);
      expect(qrlDescriptor.height).to.equal(0);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });
  });

  describe('newQRLDescriptorFromExtendedSeed', () => {
    it('should create a QRLDescriptor instance', () => {
      const extendedSeeds = new Uint8Array([
        9, 4, 6, 9, 1, 12, 2, 9, 12, 4, 6, 13, 3, 2, 12, 6, 12, 4, 2, 5, 4, 12, 8, 11, 13, 15, 11, 0, 7, 0, 9, 4, 2, 2,
        6, 8, 8, 3, 14, 3, 8, 6, 2, 6, 0, 9, 3, 7, 6, 14, 14,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of extendedSeeds array is not EXTENDED_SEED_SIZE', () => {
      const extendedSeeds = new Uint8Array([4]);

      expect(() => newQRLDescriptorFromExtendedSeed(extendedSeeds)).to.throw(
        `extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`
      );
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[9, 4 ...]', () => {
      const extendedSeeds = new Uint8Array([
        9, 4, 6, 9, 1, 12, 2, 9, 12, 4, 6, 13, 3, 2, 12, 6, 12, 4, 2, 5, 4, 12, 8, 11, 13, 15, 11, 0, 7, 0, 9, 4, 2, 2,
        6, 8, 8, 3, 14, 3, 8, 6, 2, 6, 0, 9, 3, 7, 6, 14, 14,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(9);
      expect(qrlDescriptor.signatureType).to.equal(0);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[92, 164 ...]', () => {
      const extendedSeeds = new Uint8Array([
        92, 164, 78, 27, 20, 148, 230, 46, 92, 113, 65, 34, 150, 203, 3, 100, 29, 2, 96, 69, 148, 129, 243, 182, 138,
        181, 219, 223, 88, 211, 202, 170, 80, 146, 155, 239, 68, 23, 154, 138, 23, 191, 63, 2, 164, 29, 14, 132, 205,
        61, 3,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(12);
      expect(qrlDescriptor.signatureType).to.equal(5);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(10);
    });

    it('should create a QRLDescriptor instance, with extendedSeeds[141, 9 ...]', () => {
      const extendedSeeds = new Uint8Array([
        141, 9, 185, 102, 123, 177, 144, 213, 151, 52, 135, 96, 10, 106, 46, 116, 23, 26, 151, 50, 129, 183, 119, 188,
        127, 163, 199, 171, 203, 203, 119, 89, 97, 241, 67, 13, 170, 98, 155, 107, 164, 40, 146, 204, 4, 236, 224, 210,
        67, 0, 161,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedSeed(extendedSeeds);

      expect(qrlDescriptor.hashFunction).to.equal(13);
      expect(qrlDescriptor.signatureType).to.equal(8);
      expect(qrlDescriptor.height).to.equal(18);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });
  });

  describe('newQRLDescriptorFromExtendedPk', () => {
    it('should create a QRLDescriptor instance', () => {
      const extendedPk = new Uint8Array([
        67, 5, 63, 239, 190, 194, 90, 63, 116, 243, 240, 154, 214, 84, 217, 78, 125, 166, 75, 89, 30, 14, 209, 0, 144,
        140, 211, 67, 221, 165, 114, 72, 145, 39, 81, 9, 89, 223, 3, 250, 163, 63, 174, 140, 188, 164, 68, 243, 115, 43,
        91, 23, 193, 134, 51, 185, 227, 253, 178, 110, 86, 240, 112, 89, 52, 33, 86,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(Object.getOwnPropertyNames(qrlDescriptor)).to.deep.equal([
        'hashFunction',
        'signatureType',
        'height',
        'addrFormatType',
      ]);
    });

    it('should throw an error if the size of extendedPk array is not EXTENDED_PK_SIZE', () => {
      const extendedPk = new Uint8Array([56, 87]);

      expect(() => newQRLDescriptorFromExtendedPk(extendedPk)).to.throw(
        `extendedPk should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`
      );
    });

    it('should create a QRLDescriptor instance, with extendedPk[84, 156 ...]', () => {
      const extendedPk = new Uint8Array([
        67, 5, 63, 239, 190, 194, 90, 63, 116, 243, 240, 154, 214, 84, 217, 78, 125, 166, 75, 89, 30, 14, 209, 0, 144,
        140, 211, 67, 221, 165, 114, 72, 145, 39, 81, 9, 89, 223, 3, 250, 163, 63, 174, 140, 188, 164, 68, 243, 115, 43,
        91, 23, 193, 134, 51, 185, 227, 253, 178, 110, 86, 240, 112, 89, 52, 33, 86,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(3);
      expect(qrlDescriptor.signatureType).to.equal(4);
      expect(qrlDescriptor.height).to.equal(10);
      expect(qrlDescriptor.addrFormatType).to.equal(0);
    });

    it('should create a QRLDescriptor instance, with extendedPk[109, 20 ...]', () => {
      const extendedPk = new Uint8Array([
        109, 20, 218, 222, 200, 116, 109, 209, 45, 84, 242, 238, 1, 215, 18, 124, 77, 222, 142, 183, 218, 224, 123, 109,
        105, 152, 164, 128, 116, 30, 156, 246, 219, 20, 150, 250, 207, 120, 22, 20, 133, 179, 53, 87, 130, 204, 183,
        234, 109, 94, 55, 187, 242, 43, 179, 19, 10, 81, 128, 151, 20, 245, 207, 216, 18, 235, 1,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(13);
      expect(qrlDescriptor.signatureType).to.equal(6);
      expect(qrlDescriptor.height).to.equal(8);
      expect(qrlDescriptor.addrFormatType).to.equal(1);
    });

    it('should create a QRLDescriptor instance, with extendedPk[102, 25 ...]', () => {
      const extendedPk = new Uint8Array([
        102, 25, 153, 94, 80, 214, 241, 97, 162, 182, 144, 99, 214, 38, 231, 227, 119, 188, 178, 202, 22, 56, 171, 125,
        111, 0, 211, 152, 129, 100, 89, 132, 105, 56, 52, 86, 112, 147, 92, 125, 232, 52, 36, 136, 247, 132, 140, 97,
        32, 216, 217, 65, 247, 236, 104, 107, 3, 57, 23, 172, 136, 102, 73, 78, 88, 47, 212,
      ]);
      const qrlDescriptor = newQRLDescriptorFromExtendedPk(extendedPk);

      expect(qrlDescriptor.hashFunction).to.equal(6);
      expect(qrlDescriptor.signatureType).to.equal(6);
      expect(qrlDescriptor.height).to.equal(18);
      expect(qrlDescriptor.addrFormatType).to.equal(1);
    });
  });
});
