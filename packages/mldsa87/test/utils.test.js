import { describe, it } from 'mocha';
import { expect } from 'chai';
import { zeroize, isZero } from '../src/utils.js';

describe('Security Utilities', () => {
  describe('zeroize', () => {
    it('should zero out a buffer', () => {
      const buffer = new Uint8Array([1, 2, 3, 4, 5]);
      zeroize(buffer);
      expect(Array.from(buffer)).to.deep.equal([0, 0, 0, 0, 0]);
    });

    it('should work with an empty buffer', () => {
      const buffer = new Uint8Array(0);
      zeroize(buffer);
      expect(buffer.length).to.equal(0);
    });

    it('should work with a large buffer', () => {
      const buffer = new Uint8Array(4896); // SK size
      buffer.fill(0xff);
      zeroize(buffer);
      expect(isZero(buffer)).to.equal(true);
    });

    it('should throw for non-Uint8Array', () => {
      expect(() => zeroize([1, 2, 3])).to.throw(TypeError);
      expect(() => zeroize('test')).to.throw(TypeError);
      expect(() => zeroize(null)).to.throw(TypeError);
      expect(() => zeroize(undefined)).to.throw(TypeError);
    });
  });

  describe('isZero', () => {
    it('should return true for all-zero buffer', () => {
      const buffer = new Uint8Array(32);
      expect(isZero(buffer)).to.equal(true);
    });

    it('should return false for non-zero buffer', () => {
      const buffer = new Uint8Array(32);
      buffer[15] = 1;
      expect(isZero(buffer)).to.equal(false);
    });

    it('should return true for empty buffer', () => {
      const buffer = new Uint8Array(0);
      expect(isZero(buffer)).to.equal(true);
    });

    it('should throw for non-Uint8Array', () => {
      expect(() => isZero([0, 0, 0])).to.throw(TypeError);
      expect(() => isZero('000')).to.throw(TypeError);
    });

    it('should use constant-time comparison', () => {
      // This is a basic sanity check - we can't easily verify constant-time
      // in JavaScript, but we verify the logic is correct
      const buffer1 = new Uint8Array([1, 0, 0, 0]);
      const buffer2 = new Uint8Array([0, 0, 0, 1]);
      expect(isZero(buffer1)).to.equal(false);
      expect(isZero(buffer2)).to.equal(false);
    });
  });
});
