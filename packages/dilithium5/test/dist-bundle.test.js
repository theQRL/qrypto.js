/**
 * Smoke tests for the built ESM and CJS dist bundles.
 *
 * These verify that `npm run build` produces bundles a consumer can actually
 * import (ESM) or require (CJS) without ERR_REQUIRE_ESM or other loader
 * errors.
 */
import { expect } from 'chai';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const exec = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const NODE = process.execPath;

function run(script, opts = {}) {
  const args = opts.cjs ? ['-e', script] : ['--input-type=module', '-e', script];
  return exec(NODE, args, { cwd: ROOT, timeout: 30000 });
}

describe('dist bundle smoke tests', () => {
  describe('ESM (dist/mjs/dilithium5.js)', () => {
    it('imports and generates a keypair', async () => {
      const { stdout } = await run(`
        import { cryptoSignKeypair, CryptoPublicKeyBytes, CryptoSecretKeyBytes } from './dist/mjs/dilithium5.js';
        const pk = new Uint8Array(CryptoPublicKeyBytes);
        const sk = new Uint8Array(CryptoSecretKeyBytes);
        cryptoSignKeypair(null, pk, sk);
        console.log(pk.length === CryptoPublicKeyBytes && sk.length === CryptoSecretKeyBytes);
      `);
      expect(stdout.trim()).to.equal('true');
    });

    it('sign and verify round-trip', async () => {
      const { stdout } = await run(`
        import { cryptoSignKeypair, cryptoSignSignature, cryptoSignVerify, CryptoBytes, CryptoPublicKeyBytes, CryptoSecretKeyBytes } from './dist/mjs/dilithium5.js';
        const pk = new Uint8Array(CryptoPublicKeyBytes);
        const sk = new Uint8Array(CryptoSecretKeyBytes);
        cryptoSignKeypair(null, pk, sk);
        const msg = new TextEncoder().encode('test');
        const sig = new Uint8Array(CryptoBytes);
        cryptoSignSignature(sig, msg, sk);
        console.log(cryptoSignVerify(sig, msg, pk));
      `);
      expect(stdout.trim()).to.equal('true');
    });
  });

  describe('CJS (dist/cjs/dilithium5.js)', () => {
    it('requires and generates a keypair', async () => {
      const { stdout } = await run(
        `
        const { cryptoSignKeypair, CryptoPublicKeyBytes, CryptoSecretKeyBytes } = require('./dist/cjs/dilithium5.js');
        const pk = new Uint8Array(CryptoPublicKeyBytes);
        const sk = new Uint8Array(CryptoSecretKeyBytes);
        cryptoSignKeypair(null, pk, sk);
        console.log(pk.length === CryptoPublicKeyBytes && sk.length === CryptoSecretKeyBytes);
      `,
        { cjs: true }
      );
      expect(stdout.trim()).to.equal('true');
    });

    it('sign and verify round-trip', async () => {
      const { stdout } = await run(
        `
        const { cryptoSignKeypair, cryptoSignSignature, cryptoSignVerify, CryptoBytes, CryptoPublicKeyBytes, CryptoSecretKeyBytes } = require('./dist/cjs/dilithium5.js');
        const pk = new Uint8Array(CryptoPublicKeyBytes);
        const sk = new Uint8Array(CryptoSecretKeyBytes);
        cryptoSignKeypair(null, pk, sk);
        const msg = new TextEncoder().encode('test');
        const sig = new Uint8Array(CryptoBytes);
        cryptoSignSignature(sig, msg, sk);
        console.log(cryptoSignVerify(sig, msg, pk));
      `,
        { cjs: true }
      );
      expect(stdout.trim()).to.equal('true');
    });
  });
});
