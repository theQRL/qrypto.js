import { expect } from 'chai';
import { describe, it } from 'mocha';
import { ENDIAN } from '../src/constants.js';
import { addrToByte, setChainAddr, setHashAddr, setKeyAndMask, shake256 } from '../src/helper.js';

describe('helper', () => {
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

  describe('setChainAddr', () => {
    it('should set the chain at index 5', () => {
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const chain = new Uint32Array([16])[0];
      const newAddr = setChainAddr(addr, chain);
      const expectedAddr = new Uint32Array([1, 2, 3, 4, 5, 16, 7, 8]);

      expect(newAddr).to.deep.equal(expectedAddr);
    });
  });

  describe('setHashAddr', () => {
    it('should set the hash at index 6', () => {
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const hash = new Uint32Array([22])[0];
      const newAddr = setHashAddr(addr, hash);
      const expectedAddr = new Uint32Array([1, 2, 3, 4, 5, 6, 22, 8]);

      expect(newAddr).to.deep.equal(expectedAddr);
    });
  });

  describe('setKeyAndMask', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const keyAndMask = new Uint32Array([17])[0];
      const newAddr = setKeyAndMask(addr, keyAndMask);
      const expectedAddr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 17]);

      expect(newAddr).to.deep.equal(expectedAddr);
    });
  });

  describe('addrToByte', () => {
    it('should add addr to bytes in case of little endian', () => {
      const getEndianFunc = () => ENDIAN.LITTLE;
      const bytes = new Uint8Array(32);
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const addrBytes = addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = new Uint8Array([
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8,
      ]);

      expect(addrBytes).to.deep.equal(expectedUint8Array);
    });

    it('should add addr to bytes in case of big endian', () => {
      const getEndianFunc = () => ENDIAN.BIG;
      const bytes = new Uint8Array(32);
      const addr = new Uint32Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const addrBytes = addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = new Uint8Array([
        1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0,
      ]);

      expect(addrBytes).to.deep.equal(expectedUint8Array);
    });
  });
});
