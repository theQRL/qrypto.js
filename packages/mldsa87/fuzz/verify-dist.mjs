#!/usr/bin/env node

import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cryptoSignKeypair, cryptoSignSignature, cryptoSignVerify as verifySrc } from '../src/sign.js';
import {
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
  CTILDEBytes,
  L,
  PolyZPackedBytes,
} from '../src/const.js';
import { PRNG } from '../../../scripts/fuzz/engine/prng.mjs';
import { mutate } from '../../../scripts/fuzz/engine/mutate-bytes.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, 'corpus', 'verify-dist', 'interesting');
const HINT_REGION_OFFSET = CTILDEBytes + L * PolyZPackedBytes;

const distMjs = await import('../dist/mjs/mldsa87.js');
const verifyMjs = distMjs.cryptoSignVerify;

let verifyCjs = null;
try {
  const require = createRequire(import.meta.url);
  const distCjs = require('../dist/cjs/mldsa87.js');
  verifyCjs = distCjs.cryptoSignVerify;
} catch (e) {
  process.stderr.write(`[warn] CJS dist import failed, continuing with src vs ESM only: ${e.message}\n`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { seed: Date.now(), iterations: 100_000 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--seed' && i + 1 < args.length) opts.seed = Number(args[++i]);
    else if (args[i] === '--iterations' && i + 1 < args.length) opts.iterations = Number(args[++i]);
  }
  return opts;
}

function toHex(buf) {
  return Buffer.from(buf).toString('hex');
}

function cloneBytes(buf) {
  return new Uint8Array(buf);
}

function generateBaseTuple(seedVal) {
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  const prng = new PRNG(seedVal);
  const keySeed = prng.nextBytes(32);
  cryptoSignKeypair(keySeed, pk, sk);

  const msgLen = prng.nextRange(1, 256);
  const msg = prng.nextBytes(msgLen);

  const ctxLen = prng.nextRange(0, 32);
  const ctx = ctxLen > 0 ? prng.nextBytes(ctxLen) : new Uint8Array(0);

  const sig = new Uint8Array(CryptoBytes);
  cryptoSignSignature(sig, msg, sk, false, ctx);

  return { pk, sk, sig, msg, ctx };
}

function callVerify(fn, sig, msg, pk, ctx) {
  try {
    return { result: fn(sig, msg, pk, ctx), error: null };
  } catch (e) {
    return { result: 'threw', error: e.message || String(e) };
  }
}

function saveCase(tag, data) {
  mkdirSync(CORPUS_DIR, { recursive: true });
  const base = `${tag}_iter${data.iteration}_${Date.now()}`;
  const serialized = {
    tag,
    seed: data.seed,
    iteration: data.iteration,
    mutationFamily: data.mutationFamily,
    mutatedField: data.mutatedField,
    baseTupleIndex: data.baseTupleIndex,
    bytesChanged: data.bytesChanged,
    sig: toHex(data.sig),
    msg: toHex(data.msg),
    pk: toHex(data.pk),
    ctx: toHex(data.ctx),
    srcResult: String(data.srcResult),
    mjsResult: String(data.mjsResult),
    cjsResult: data.cjsResult != null ? String(data.cjsResult) : null,
    srcError: data.srcError,
    mjsError: data.mjsError,
    cjsError: data.cjsError,
  };
  writeFileSync(join(CORPUS_DIR, `${base}.json`), JSON.stringify(serialized, null, 2));

  if (data.sig instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_sig.bin`), data.sig);
  }
  if (data.pk instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_pk.bin`), data.pk);
  }
  if (data.msg instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_msg.bin`), data.msg);
  }

  return `${base}.json`;
}

function main() {
  const opts = parseArgs();
  const rng = new PRNG(opts.seed);

  process.stderr.write(`[*] verify-dist fuzzer starting\n`);
  process.stderr.write(`[*] seed=${opts.seed} iterations=${opts.iterations}\n`);
  process.stderr.write(`[*] CJS available: ${verifyCjs !== null}\n`);

  process.stderr.write(`[*] Generating 10 base corpus tuples...\n`);
  const corpus = [];
  for (let i = 0; i < 10; i++) {
    try {
      corpus.push(generateBaseTuple(opts.seed + i * 7919));
    } catch (e) {
      process.stderr.write(`[!] Failed to generate base tuple ${i}: ${e.message}\n`);
      process.exit(2);
    }
  }

  for (let i = 0; i < corpus.length; i++) {
    const t = corpus[i];
    const srcOk = verifySrc(t.sig, t.msg, t.pk, t.ctx);
    const mjsOk = verifyMjs(t.sig, t.msg, t.pk, t.ctx);
    if (!srcOk || !mjsOk) {
      process.stderr.write(`[!] Base tuple ${i} does not verify (src=${srcOk} mjs=${mjsOk})\n`);
      process.exit(2);
    }
    if (verifyCjs) {
      const cjsOk = verifyCjs(t.sig, t.msg, t.pk, t.ctx);
      if (!cjsOk) {
        process.stderr.write(`[!] Base tuple ${i} does not verify via CJS\n`);
        process.exit(2);
      }
    }
  }
  process.stderr.write(`[*] All 10 base tuples verify across all variants. Starting fuzz loop.\n`);

  let divergenceCount = 0;
  let falseAcceptCount = 0;
  const startTime = Date.now();

  function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  for (let iter = 0; iter < opts.iterations; iter++) {
    try {
      const roll = rng.nextFloat();
      let mutSig, mutMsg, mutPk, mutCtx;
      let mutatedField;
      let mutationFamily;
      let baseIdx;

      if (roll < 0.10) {
        mutationFamily = 'cross-splice';
        mutatedField = 'cross';
        baseIdx = rng.nextUint32() % corpus.length;
        let otherIdx;
        do {
          otherIdx = rng.nextUint32() % corpus.length;
        } while (otherIdx === baseIdx && corpus.length > 1);
        mutSig = cloneBytes(corpus[baseIdx].sig);
        mutPk = cloneBytes(corpus[otherIdx].pk);
        mutMsg = cloneBytes(corpus[otherIdx].msg);
        mutCtx = cloneBytes(corpus[otherIdx].ctx);
      } else {
        baseIdx = rng.nextUint32() % corpus.length;
        const base = corpus[baseIdx];
        mutSig = cloneBytes(base.sig);
        mutPk = cloneBytes(base.pk);
        mutMsg = cloneBytes(base.msg);
        mutCtx = cloneBytes(base.ctx);

        if (roll < 0.50) {
          mutationFamily = 'sig-mutate';
          mutatedField = 'sig';
          mutSig = mutate(mutSig, rng, { hintOffset: HINT_REGION_OFFSET });
        } else if (roll < 0.70) {
          mutationFamily = 'pk-mutate';
          mutatedField = 'pk';
          mutPk = mutate(mutPk, rng);
        } else if (roll < 0.90) {
          mutationFamily = 'msg-mutate';
          mutatedField = 'msg';
          mutMsg = mutate(mutMsg, rng);
        } else {
          mutationFamily = 'ctx-mutate';
          mutatedField = 'ctx';
          const newLen = rng.nextRange(0, 256);
          mutCtx = rng.nextBytes(newLen);
        }
      }

      const base = corpus[baseIdx];
      const bytesChanged =
        mutSig.length !== base.sig.length ||
        mutPk.length !== base.pk.length ||
        mutMsg.length !== base.msg.length ||
        mutCtx.length !== base.ctx.length ||
        !arraysEqual(mutSig, base.sig) ||
        !arraysEqual(mutPk, base.pk) ||
        !arraysEqual(mutMsg, base.msg) ||
        !arraysEqual(mutCtx, base.ctx);

      const src = callVerify(verifySrc, mutSig, mutMsg, mutPk, mutCtx);
      const mjs = callVerify(verifyMjs, mutSig, mutMsg, mutPk, mutCtx);
      const cjs = verifyCjs ? callVerify(verifyCjs, mutSig, mutMsg, mutPk, mutCtx) : null;

      const srcR = src.result;
      const mjsR = mjs.result;
      const cjsR = cjs?.result ?? null;

      let diverged = false;
      if (srcR !== mjsR) diverged = true;
      if (cjsR !== null && (cjsR !== srcR || cjsR !== mjsR)) diverged = true;

      const caseMeta = {
        seed: opts.seed, iteration: iter, mutationFamily, mutatedField,
        baseTupleIndex: baseIdx, bytesChanged,
        sig: mutSig, msg: mutMsg, pk: mutPk, ctx: mutCtx,
        srcResult: srcR, mjsResult: mjsR, cjsResult: cjsR,
        srcError: src.error, mjsError: mjs.error, cjsError: cjs?.error ?? null,
      };

      if (diverged) {
        divergenceCount++;
        process.stderr.write(
          `\n[!!!] DIVERGENCE at iter=${iter} family=${mutationFamily} field=${mutatedField}\n` +
          `  src=${srcR} mjs=${mjsR} cjs=${cjsR}\n`,
        );
        saveCase('DIVERGENCE', caseMeta);
      }

      if (bytesChanged && (srcR === true || mjsR === true || cjsR === true)) {
        falseAcceptCount++;
        process.stderr.write(
          `\n[!!!] FALSE ACCEPT at iter=${iter} family=${mutationFamily} field=${mutatedField}\n` +
          `  src=${srcR} mjs=${mjsR} cjs=${cjsR} bytesChanged=${bytesChanged}\n`,
        );
        saveCase('FALSE_ACCEPT', caseMeta);
      }

      if (iter > 0 && iter % 1000 === 0) {
        const elapsedSec = ((Date.now() - startTime) / 1000).toFixed(1);
        process.stderr.write(
          `[*] iter=${iter}/${opts.iterations} divergences=${divergenceCount} falseAccepts=${falseAcceptCount} elapsed=${elapsedSec}s\n`,
        );
      }
    } catch (e) {
      process.stderr.write(`[!] Fuzzer internal error at iter=${iter}: ${e.message}\n`);
    }
  }

  const totalSec = ((Date.now() - startTime) / 1000).toFixed(1);
  process.stderr.write(`\n[*] === SUMMARY ===\n`);
  process.stderr.write(`[*] Total iterations: ${opts.iterations}\n`);
  process.stderr.write(`[*] Divergences:      ${divergenceCount}\n`);
  process.stderr.write(`[*] False accepts:    ${falseAcceptCount}\n`);
  process.stderr.write(`[*] Elapsed:          ${totalSec}s\n`);
  process.stderr.write(`[*] Seed:             ${opts.seed}\n`);
  process.stderr.write(`[*] Corpus dir:       ${CORPUS_DIR}\n`);

  if (divergenceCount > 0) process.exit(2);
  if (falseAcceptCount > 0) process.exit(1);
  process.exit(0);
}

try {
  main();
} catch (e) {
  process.stderr.write(`[FATAL] ${e.stack || e.message}\n`);
  process.exit(2);
}
