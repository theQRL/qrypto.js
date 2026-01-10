#!/usr/bin/env node
/**
 * Generate an ML-DSA-87 signature using qrypto.js for cross-verification.
 * Outputs: /tmp/qrypto_mldsa87_pk.bin, /tmp/qrypto_mldsa87_sig.bin, /tmp/qrypto_mldsa87_msg.bin, /tmp/qrypto_mldsa87_ctx.bin
 *
 * Note: Uses a fixed seed for deterministic cross-verification.
 * ML-DSA-87 does NOT pre-hash the seed (unlike Dilithium5), so raw seed is used directly.
 */

import { writeFileSync } from 'fs';
import {
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
} from '../../packages/mldsa87/src/const.js';
import { cryptoSignKeypair, cryptoSign } from '../../packages/mldsa87/src/sign.js';

// Fixed test seed (raw seed - no pre-hashing needed for ML-DSA-87)
const SEED = '0000000000000000000000000000000000000000000000000000000000000000';
const TEST_MESSAGE = 'Cross-verification test message for ML-DSA-87';
const CONTEXT = 'ZOND'; // Standard context used by QRL

console.log('=== qrypto.js ML-DSA-87 Signature Generation ===');
console.log(`Seed: ${SEED}`);
console.log(`Message: "${TEST_MESSAGE}"`);
console.log(`Context: "${CONTEXT}"`);

// Generate keypair
const seed = Buffer.from(SEED, 'hex');
const pk = new Uint8Array(CryptoPublicKeyBytes);
const sk = new Uint8Array(CryptoSecretKeyBytes);
cryptoSignKeypair(seed, pk, sk);

console.log(`Public key size: ${pk.length} bytes`);
console.log(`Secret key size: ${sk.length} bytes`);

// Sign message with context (non-randomized for determinism)
const msg = Buffer.from(TEST_MESSAGE, 'utf8');
const ctx = Buffer.from(CONTEXT, 'utf8');
const signedMsg = cryptoSign(msg, sk, false, ctx);
const sig = signedMsg.slice(0, CryptoBytes);

console.log(`Signature size: ${sig.length} bytes`);
console.log(`Public key (first 32 bytes): ${Buffer.from(pk.slice(0, 32)).toString('hex')}`);
console.log(`Signature (first 32 bytes): ${Buffer.from(sig.slice(0, 32)).toString('hex')}`);

// Write output files for go-qrllib to verify
writeFileSync('/tmp/qrypto_mldsa87_pk.bin', pk);
writeFileSync('/tmp/qrypto_mldsa87_sig.bin', sig);
writeFileSync('/tmp/qrypto_mldsa87_msg.bin', msg);
writeFileSync('/tmp/qrypto_mldsa87_ctx.bin', ctx);

// Also write hex versions for debugging
writeFileSync('/tmp/qrypto_mldsa87_pk.hex', Buffer.from(pk).toString('hex'));
writeFileSync('/tmp/qrypto_mldsa87_sig.hex', Buffer.from(sig).toString('hex'));

console.log('\nOutput files written:');
console.log('  /tmp/qrypto_mldsa87_pk.bin');
console.log('  /tmp/qrypto_mldsa87_sig.bin');
console.log('  /tmp/qrypto_mldsa87_msg.bin');
console.log('  /tmp/qrypto_mldsa87_ctx.bin');
console.log('\n✓ qrypto.js signature generation complete');
