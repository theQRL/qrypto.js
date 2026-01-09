#!/usr/bin/env node
/**
 * Generate a Dilithium5 signature using qrypto.js for cross-verification.
 * Outputs: /tmp/qrypto_dilithium5_pk.bin, /tmp/qrypto_dilithium5_sig.bin, /tmp/qrypto_dilithium5_msg.bin
 *
 * Note: Uses a fixed seed for deterministic cross-verification.
 * The seed is pre-hashed with SHAKE256 to match go-qrllib's internal processing.
 */

import { writeFileSync } from 'fs';
import {
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
} from '../../packages/dilithium5/src/const.js';
import { cryptoSignKeypair, cryptoSign } from '../../packages/dilithium5/src/sign.js';

// Fixed test seed (this is the SHAKE256 hash of all-zeros seed, matching go-qrllib's internal format)
// go-qrllib does: hashedSeed = SHAKE256(seed)[:32] before key generation
// So we use the hashedSeed directly to get matching keys
const HASHED_SEED = 'f5977c8283546a63723bc31d2619124f11db4658643336741df81757d5ad3062';
const TEST_MESSAGE = 'Cross-verification test message for Dilithium5';

console.log('=== qrypto.js Dilithium5 Signature Generation ===');
console.log(`Hashed seed: ${HASHED_SEED}`);
console.log(`Message: "${TEST_MESSAGE}"`);

// Generate keypair
const seed = Buffer.from(HASHED_SEED, 'hex');
const pk = new Uint8Array(CryptoPublicKeyBytes);
const sk = new Uint8Array(CryptoSecretKeyBytes);
cryptoSignKeypair(seed, pk, sk);

console.log(`Public key size: ${pk.length} bytes`);
console.log(`Secret key size: ${sk.length} bytes`);

// Sign message (non-randomized for determinism)
const msg = Buffer.from(TEST_MESSAGE, 'utf8');
const signedMsg = cryptoSign(msg, sk, false);
const sig = signedMsg.slice(0, CryptoBytes);

console.log(`Signature size: ${sig.length} bytes`);
console.log(`Public key (first 32 bytes): ${Buffer.from(pk.slice(0, 32)).toString('hex')}`);
console.log(`Signature (first 32 bytes): ${Buffer.from(sig.slice(0, 32)).toString('hex')}`);

// Write output files for go-qrllib to verify
writeFileSync('/tmp/qrypto_dilithium5_pk.bin', pk);
writeFileSync('/tmp/qrypto_dilithium5_sig.bin', sig);
writeFileSync('/tmp/qrypto_dilithium5_msg.bin', msg);

// Also write hex versions for debugging
writeFileSync('/tmp/qrypto_dilithium5_pk.hex', Buffer.from(pk).toString('hex'));
writeFileSync('/tmp/qrypto_dilithium5_sig.hex', Buffer.from(sig).toString('hex'));

console.log('\nOutput files written:');
console.log('  /tmp/qrypto_dilithium5_pk.bin');
console.log('  /tmp/qrypto_dilithium5_sig.bin');
console.log('  /tmp/qrypto_dilithium5_msg.bin');
console.log('\n✓ qrypto.js signature generation complete');
