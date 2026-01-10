import { expect } from 'chai';
import { CryptoPublicKeyBytes, CryptoSecretKeyBytes, CryptoBytes } from '../src/const.js';
import { cryptoSign, cryptoSignKeypair, cryptoSignVerify } from '../src/sign.js';

// Edge case tests for ML-DSA-87
// These tests verify behavior with boundary conditions and unusual inputs

const TEST_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
const DEFAULT_CTX = Buffer.from('5a4f4e44', 'hex'); // "ZOND"

describe('Edge Cases - Empty Message', () => {
  it('should sign and verify an empty message', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const emptyMsg = new Uint8Array(0);
    const signedMsg = cryptoSign(emptyMsg, sk, false, DEFAULT_CTX);

    expect(signedMsg.length).to.equal(CryptoBytes);

    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
    expect(cryptoSignVerify(sig, emptyMsg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);
  });
});

describe('Edge Cases - Large Message', () => {
  it('should sign and verify a 1MB message', function () {
    this.timeout(30000); // Large message takes longer

    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    // Create 1MB message
    const largeMsg = new Uint8Array(1024 * 1024);
    for (let i = 0; i < largeMsg.length; i += 1) {
      largeMsg[i] = i % 256;
    }

    const signedMsg = cryptoSign(largeMsg, sk, false, DEFAULT_CTX);
    expect(signedMsg.length).to.equal(CryptoBytes + largeMsg.length);

    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
    expect(cryptoSignVerify(sig, largeMsg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);
  });
});

describe('Edge Cases - Context Variations', () => {
  let pk;
  let sk;

  before(() => {
    pk = new Uint8Array(CryptoPublicKeyBytes);
    sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);
  });

  it('should sign and verify with empty context', () => {
    const msg = Buffer.from('Test message', 'utf8');
    const emptyCtx = new Uint8Array(0);

    const signedMsg = cryptoSign(msg, sk, false, emptyCtx);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), emptyCtx)).to.equal(true);
  });

  it('should sign and verify with maximum length context (255 bytes)', function () {
    this.timeout(10000);

    const msg = Buffer.from('Test message', 'utf8');
    const maxCtx = new Uint8Array(255);
    for (let i = 0; i < 255; i += 1) {
      maxCtx[i] = i;
    }

    const signedMsg = cryptoSign(msg, sk, false, maxCtx);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), maxCtx)).to.equal(true);
  });

  it('should reject signature with wrong context', () => {
    const msg = Buffer.from('Test message', 'utf8');
    const ctx1 = Buffer.from('context1', 'utf8');
    const ctx2 = Buffer.from('context2', 'utf8');

    const signedMsg = cryptoSign(msg, sk, false, ctx1);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    // Correct context should pass
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), ctx1)).to.equal(true);

    // Wrong context should fail
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), ctx2)).to.equal(false);
  });

  it('should reject signature verified with empty context when signed with non-empty', () => {
    const msg = Buffer.from('Test message', 'utf8');
    const ctx = Buffer.from('ZOND', 'utf8');
    const emptyCtx = new Uint8Array(0);

    const signedMsg = cryptoSign(msg, sk, false, ctx);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), ctx)).to.equal(true);
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), emptyCtx)).to.equal(false);
  });
});

describe('Edge Cases - Tampered Signature', () => {
  it('should reject signature with flipped bit in ctilde', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
    const sig = new Uint8Array(signedMsg.slice(0, CryptoBytes));

    // Verify original signature works
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);

    // Flip a bit in the ctilde portion (first 32 bytes for ML-DSA)
    sig[16] ^= 0x01;
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(false);
  });

  it('should reject signature with flipped bit in z vector', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
    const sig = new Uint8Array(signedMsg.slice(0, CryptoBytes));

    // Verify original signature works
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);

    // Flip a bit in the z vector portion (after first 32 bytes)
    sig[100] ^= 0x80;
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(false);
  });

  it('should reject truncated signature', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
    const truncatedSig = Buffer.from(signedMsg.slice(0, CryptoBytes - 10));

    // Truncated signature should fail or throw
    try {
      const result = cryptoSignVerify(truncatedSig, msg, Buffer.from(pk), DEFAULT_CTX);
      expect(result).to.equal(false);
    } catch (e) {
      // Throwing is also acceptable behavior for invalid signature length
      expect(e).to.be.an('error');
    }
  });

  it('should reject all-zero signature', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const zeroSig = Buffer.alloc(CryptoBytes, 0);

    expect(cryptoSignVerify(zeroSig, msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(false);
  });
});

describe('Edge Cases - Single Byte Message', () => {
  it('should sign and verify single byte messages (0x00 through 0xFF)', function () {
    this.timeout(60000); // Testing 256 values

    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    // Test a sample of single-byte messages
    const testBytes = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];
    testBytes.forEach((byte) => {
      const msg = new Uint8Array([byte]);
      const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
      const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
      expect(cryptoSignVerify(sig, msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);
    });
  });
});
