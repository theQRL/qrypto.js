import { expect } from 'chai';
import {
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
  SeedBytes,
  TRBytes,
  CTILDEBytes,
  K,
  L,
  ETA,
  TAU,
  BETA,
  GAMMA1,
  GAMMA2,
  OMEGA,
  Q,
  N,
  D,
} from '../src/const.js';
import { cryptoSign, cryptoSignKeypair, cryptoSignOpen, cryptoSignVerify } from '../src/sign.js';

// Known Answer Tests (KAT) for ML-DSA-87
// These tests verify:
// 1. Key/signature sizes match ML-DSA-87 specification
// 2. Keypair generation is deterministic
// 3. Signature generation is deterministic (non-randomized)
// 4. Sign/verify round-trip works correctly

// Test seeds
const TEST_SEEDS = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff',
];

// Default context for ML-DSA-87 (ZOND)
const DEFAULT_CTX = Buffer.from('5a4f4e44', 'hex'); // "ZOND"

describe('KAT - Key Sizes', () => {
  it('should have correct ML-DSA-87 public key size (2592 bytes)', () => {
    expect(CryptoPublicKeyBytes).to.equal(2592);
  });

  it('should have correct ML-DSA-87 secret key size (4896 bytes)', () => {
    // SK = 2*SEED_BYTES + TR_BYTES + L*POLY_ETA_PACKED + K*POLY_ETA_PACKED + K*POLY_T0_PACKED
    // SK = 2*32 + 64 + 7*96 + 8*96 + 8*416 = 64 + 64 + 672 + 768 + 3328 = 4896
    expect(CryptoSecretKeyBytes).to.equal(4896);
  });

  it('should have correct ML-DSA-87 signature size (4627 bytes)', () => {
    // SIG = CTILDE_BYTES + L*POLY_Z_PACKED + OMEGA + K
    // SIG = 64 + 7*640 + 75 + 8 = 64 + 4480 + 83 = 4627
    expect(CryptoBytes).to.equal(4627);
  });

  it('should have correct seed size (32 bytes)', () => {
    expect(SeedBytes).to.equal(32);
  });

  it('should have correct TR size (64 bytes)', () => {
    expect(TRBytes).to.equal(64);
  });

  it('should have correct CTILDE size (64 bytes)', () => {
    // ML-DSA-87 uses 64-byte challenge (vs 32 in Dilithium5)
    expect(CTILDEBytes).to.equal(64);
  });
});

describe('KAT - ML-DSA-87 Parameters', () => {
  it('should have correct K parameter (8)', () => {
    expect(K).to.equal(8);
  });

  it('should have correct L parameter (7)', () => {
    expect(L).to.equal(7);
  });

  it('should have correct ETA parameter (2)', () => {
    expect(ETA).to.equal(2);
  });

  it('should have correct TAU parameter (60)', () => {
    expect(TAU).to.equal(60);
  });

  it('should have correct BETA parameter (120)', () => {
    expect(BETA).to.equal(120);
  });

  it('should have correct GAMMA1 parameter (2^19)', () => {
    expect(GAMMA1).to.equal(1 << 19);
  });

  it('should have correct GAMMA2 parameter ((Q-1)/32)', () => {
    expect(GAMMA2).to.equal(Math.floor((Q - 1) / 32));
  });

  it('should have correct OMEGA parameter (75)', () => {
    expect(OMEGA).to.equal(75);
  });

  it('should have correct Q parameter (8380417)', () => {
    expect(Q).to.equal(8380417);
  });

  it('should have correct N parameter (256)', () => {
    expect(N).to.equal(256);
  });

  it('should have correct D parameter (13)', () => {
    expect(D).to.equal(13);
  });
});

describe('KAT - Deterministic Keypair', () => {
  TEST_SEEDS.forEach((seedHex, i) => {
    it(`should generate identical keypairs from same seed (vector ${i})`, () => {
      const seed = Buffer.from(seedHex, 'hex');

      // Generate keypair twice
      const pk1 = new Uint8Array(CryptoPublicKeyBytes);
      const sk1 = new Uint8Array(CryptoSecretKeyBytes);
      cryptoSignKeypair(seed, pk1, sk1);

      const pk2 = new Uint8Array(CryptoPublicKeyBytes);
      const sk2 = new Uint8Array(CryptoSecretKeyBytes);
      cryptoSignKeypair(seed, pk2, sk2);

      // Should be identical
      expect(Buffer.from(pk1).toString('hex')).to.equal(Buffer.from(pk2).toString('hex'));
      expect(Buffer.from(sk1).toString('hex')).to.equal(Buffer.from(sk2).toString('hex'));
    });
  });
});

describe('KAT - Deterministic Signature', () => {
  const messages = [
    '',
    '48656c6c6f2c20576f726c6421', // "Hello, World!"
    '54657374206d65737361676520666f72204b415420766572696669636174696f6e',
  ];

  TEST_SEEDS.forEach((seedHex, i) => {
    it(`should generate identical signatures for same message (vector ${i})`, () => {
      const seed = Buffer.from(seedHex, 'hex');
      const msg = Buffer.from(messages[i] || '', 'hex');

      const pk = new Uint8Array(CryptoPublicKeyBytes);
      const sk = new Uint8Array(CryptoSecretKeyBytes);
      cryptoSignKeypair(seed, pk, sk);

      // Sign twice (non-randomized) with same context
      const sig1 = cryptoSign(msg, sk, false, DEFAULT_CTX);
      const sig2 = cryptoSign(msg, sk, false, DEFAULT_CTX);

      // Should be identical
      expect(Buffer.from(sig1).toString('hex')).to.equal(Buffer.from(sig2).toString('hex'));
    });
  });
});

describe('KAT - Sign/Verify Round Trip', () => {
  TEST_SEEDS.forEach((seedHex, i) => {
    it(`should sign and verify correctly (vector ${i})`, () => {
      const seed = Buffer.from(seedHex, 'hex');
      const msg = Buffer.from('Test message for verification', 'utf8');

      const pk = new Uint8Array(CryptoPublicKeyBytes);
      const sk = new Uint8Array(CryptoSecretKeyBytes);
      cryptoSignKeypair(seed, pk, sk);

      // Sign with context
      const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
      expect(signedMsg.length).to.equal(CryptoBytes + msg.length);

      // Open (verify and extract message)
      const openedMsg = cryptoSignOpen(Buffer.from(signedMsg), Buffer.from(pk), DEFAULT_CTX);
      expect(openedMsg).to.not.equal(undefined);
      expect(Buffer.from(openedMsg).toString('utf8')).to.equal('Test message for verification');

      // Verify signature directly
      const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));
      expect(cryptoSignVerify(sig, msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);
    });
  });
});

describe('KAT - Wrong Key Rejection', () => {
  it('should reject signature with wrong public key', () => {
    const seed1 = Buffer.from(TEST_SEEDS[0], 'hex');
    const seed2 = Buffer.from(TEST_SEEDS[1], 'hex');
    const msg = Buffer.from('Test message', 'utf8');

    // Generate two keypairs
    const pk1 = new Uint8Array(CryptoPublicKeyBytes);
    const sk1 = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(seed1, pk1, sk1);

    const pk2 = new Uint8Array(CryptoPublicKeyBytes);
    const sk2 = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(seed2, pk2, sk2);

    // Sign with sk1
    const signedMsg = cryptoSign(msg, sk1, false, DEFAULT_CTX);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    // Verify with correct key should pass
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk1), DEFAULT_CTX)).to.equal(true);

    // Verify with wrong key should fail
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk2), DEFAULT_CTX)).to.equal(false);
  });
});

describe('KAT - Wrong Message Rejection', () => {
  it('should reject signature with modified message', () => {
    const seed = Buffer.from(TEST_SEEDS[0], 'hex');
    const msg = Buffer.from('Test message', 'utf8');
    const wrongMsg = Buffer.from('Wrong message', 'utf8');

    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(seed, pk, sk);

    // Sign original message
    const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    // Verify with correct message should pass
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);

    // Verify with wrong message should fail
    expect(cryptoSignVerify(sig, wrongMsg, Buffer.from(pk), DEFAULT_CTX)).to.equal(false);
  });
});

describe('KAT - Wrong Context Rejection', () => {
  it('should reject signature with wrong context', () => {
    const seed = Buffer.from(TEST_SEEDS[0], 'hex');
    const msg = Buffer.from('Test message', 'utf8');
    const wrongCtx = Buffer.from('WRONGCTX', 'utf8');

    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(seed, pk, sk);

    // Sign with correct context
    const signedMsg = cryptoSign(msg, sk, false, DEFAULT_CTX);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    // Verify with correct context should pass
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(true);

    // Verify with wrong context should fail
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), wrongCtx)).to.equal(false);
  });
});

describe('KAT - Different Seeds Different Keys', () => {
  it('should generate different keypairs from different seeds', () => {
    const pk1 = new Uint8Array(CryptoPublicKeyBytes);
    const sk1 = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(Buffer.from(TEST_SEEDS[0], 'hex'), pk1, sk1);

    const pk2 = new Uint8Array(CryptoPublicKeyBytes);
    const sk2 = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(Buffer.from(TEST_SEEDS[1], 'hex'), pk2, sk2);

    // Public keys should be different
    expect(Buffer.from(pk1).toString('hex')).to.not.equal(Buffer.from(pk2).toString('hex'));

    // Secret keys should be different
    expect(Buffer.from(sk1).toString('hex')).to.not.equal(Buffer.from(sk2).toString('hex'));
  });
});

describe('KAT - Empty Context', () => {
  it('should work with empty context', () => {
    const seed = Buffer.from(TEST_SEEDS[0], 'hex');
    const msg = Buffer.from('Test message', 'utf8');
    const emptyCtx = Buffer.alloc(0);

    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    cryptoSignKeypair(seed, pk, sk);

    // Sign with empty context
    const signedMsg = cryptoSign(msg, sk, false, emptyCtx);
    const sig = Buffer.from(signedMsg.slice(0, CryptoBytes));

    // Verify with empty context should pass
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), emptyCtx)).to.equal(true);

    // Verify with non-empty context should fail
    expect(cryptoSignVerify(sig, msg, Buffer.from(pk), DEFAULT_CTX)).to.equal(false);
  });
});
