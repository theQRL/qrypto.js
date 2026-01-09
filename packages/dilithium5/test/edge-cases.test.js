import { expect } from 'chai';
import { CryptoPublicKeyBytes, CryptoSecretKeyBytes, CryptoBytes } from '../src/const.js';
import { cryptoSign, cryptoSignKeypair, cryptoSignVerify } from '../src/sign.js';

// Edge case tests for Dilithium5 (Round 3)
// These tests verify behavior with boundary conditions and unusual inputs

const TEST_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');

describe('Edge Cases - Empty Message', () => {
  it('should sign and verify an empty message', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const emptyMsg = new Uint8Array(0);
    const signedMsg = cryptoSign(emptyMsg, sk, false);

    expect(signedMsg.length).to.equal(CryptoBytes);

    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
    expect(cryptoSignVerify(sig, emptyMsg, Buffer.from(pk))).to.equal(true);
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

    const signedMsg = cryptoSign(largeMsg, sk, false);
    expect(signedMsg.length).to.equal(CryptoBytes + largeMsg.length);

    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
    expect(cryptoSignVerify(sig, largeMsg, Buffer.from(pk))).to.equal(true);
  });
});

describe('Edge Cases - Tampered Signature', () => {
  it('should reject signature with flipped bit in ctilde', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false);
    const sig = new Uint8Array(signedMsg.slice(0, CryptoBytes));

    // Verify original signature works
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk))).to.equal(true);

    // Flip a bit in the ctilde portion (first 32 bytes)
    sig[16] ^= 0x01;
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk))).to.equal(false);
  });

  it('should reject signature with flipped bit in z vector', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false);
    const sig = new Uint8Array(signedMsg.slice(0, CryptoBytes));

    // Verify original signature works
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk))).to.equal(true);

    // Flip a bit in the z vector portion (after first 32 bytes)
    sig[100] ^= 0x80;
    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk))).to.equal(false);
  });

  it('should reject truncated signature', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false);
    const truncatedSig = Buffer.from(signedMsg.slice(0, CryptoBytes - 10));

    // Truncated signature should fail or throw
    try {
      const result = cryptoSignVerify(truncatedSig, msg, Buffer.from(pk));
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

    expect(cryptoSignVerify(zeroSig, msg, Buffer.from(pk))).to.equal(false);
  });

  it('should reject signature with all bits flipped', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');
    const signedMsg = cryptoSign(msg, sk, false);
    const sig = new Uint8Array(signedMsg.slice(0, CryptoBytes));

    // Flip all bits
    for (let i = 0; i < sig.length; i += 1) {
      sig[i] ^= 0xff;
    }

    expect(cryptoSignVerify(Buffer.from(sig), msg, Buffer.from(pk))).to.equal(false);
  });
});

describe('Edge Cases - Single Byte Message', () => {
  it('should sign and verify single byte messages', function () {
    this.timeout(60000);

    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    // Test a sample of single-byte messages
    const testBytes = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];
    testBytes.forEach((byte) => {
      const msg = new Uint8Array([byte]);
      const signedMsg = cryptoSign(msg, sk, false);
      const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
      expect(cryptoSignVerify(sig, msg, Buffer.from(pk))).to.equal(true);
    });
  });
});

describe('Edge Cases - Binary Message Patterns', () => {
  it('should sign and verify message with all same bytes', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    // All zeros
    const allZeros = new Uint8Array(100).fill(0x00);
    let signedMsg = cryptoSign(allZeros, sk, false);
    let sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
    expect(cryptoSignVerify(sig, allZeros, Buffer.from(pk))).to.equal(true);

    // All ones
    const allOnes = new Uint8Array(100).fill(0xff);
    signedMsg = cryptoSign(allOnes, sk, false);
    sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
    expect(cryptoSignVerify(sig, allOnes, Buffer.from(pk))).to.equal(true);
  });
});

describe('Edge Cases - Multiple Signatures Same Message', () => {
  it('should produce identical signatures for same message (non-randomized)', () => {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(TEST_SEED, pk, sk);

    const msg = Buffer.from('Test message', 'utf8');

    const signedMsg1 = cryptoSign(msg, sk, false);
    const signedMsg2 = cryptoSign(msg, sk, false);

    const sig1 = Buffer.from(signedMsg1.slice(0, CryptoBytes));
    const sig2 = Buffer.from(signedMsg2.slice(0, CryptoBytes));

    expect(sig1.toString('hex')).to.equal(sig2.toString('hex'));
  });
});
