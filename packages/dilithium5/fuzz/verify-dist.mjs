#!/usr/bin/env node

import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  cryptoSignKeypair,
  cryptoSignSignature,
  cryptoSignVerify as verifySrc,
  cryptoSignOpen as openSrc,
} from '../src/sign.js';
import {
  CryptoPublicKeyBytes,
  CryptoSecretKeyBytes,
  CryptoBytes,
  SeedBytes,
  L,
  PolyZPackedBytes,
} from '../src/const.js';
import { PRNG } from '../../../scripts/fuzz/engine/prng.mjs';
import { mutate } from '../../../scripts/fuzz/engine/mutate-bytes.mjs';
import { SaveBudget } from '../../../scripts/fuzz/engine/save-budget.mjs';
import { Verdict } from '../../../scripts/fuzz/engine/verdict.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const budget = new SaveBudget();
const verdict = new Verdict();
const CORPUS_DIR = join(__dirname, 'corpus', 'verify-dist', 'interesting');
// Dilithium5 (Round 3): the challenge c is SeedBytes (32) long.
const HINT_REGION_OFFSET = SeedBytes + L * PolyZPackedBytes;

const distMjs = await import('../dist/mjs/dilithium5.js');
const verifyMjs = distMjs.cryptoSignVerify;
const openMjs = distMjs.cryptoSignOpen;

let verifyCjs = null;
let openCjs = null;
try {
  const require = createRequire(import.meta.url);
  const distCjs = require('../dist/cjs/dilithium5.js');
  verifyCjs = distCjs.cryptoSignVerify;
  openCjs = distCjs.cryptoSignOpen;
} catch (e) {
  process.stderr.write(`[warn] CJS dist import failed, continuing with src vs ESM only: ${e.message}\n`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { seed: Date.now(), iterations: 100_000, timeoutMs: 5000 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--seed' && i + 1 < args.length) opts.seed = Number(args[++i]);
    else if (args[i] === '--iterations' && i + 1 < args.length) opts.iterations = Number(args[++i]);
    else if (args[i] === '--timeout-ms' && i + 1 < args.length) opts.timeoutMs = Number(args[++i]);
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

  const sig = new Uint8Array(CryptoBytes);
  cryptoSignSignature(sig, msg, sk, false);

  return { pk, sk, sig, msg };
}

function callVerify(fn, sig, msg, pk) {
  try {
    return { result: fn(sig, msg, pk), error: null };
  } catch (e) {
    return { result: 'threw', error: e.message || String(e) };
  }
}

// Serialize a cryptoSignOpen outcome to a comparable string. Distinguishes
// rejection, success bytes, junk returns, and throws so any src↔dist
// difference in any of those shapes surfaces as a divergence.
function callOpenSerialized(fn, sm, pk) {
  try {
    const r = fn(sm, pk);
    if (r === undefined) return 'undefined';
    if (r instanceof Uint8Array) return `bytes:${toHex(r)}`;
    return `junk:${typeof r}`;
  } catch (e) {
    return `threw:${e.message || String(e)}`;
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

  process.stderr.write(`[*] verify-dist fuzzer starting (dilithium5)\n`);
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
    const srcOk = verifySrc(t.sig, t.msg, t.pk);
    const mjsOk = verifyMjs(t.sig, t.msg, t.pk);
    if (!srcOk || !mjsOk) {
      process.stderr.write(`[!] Base tuple ${i} does not verify (src=${srcOk} mjs=${mjsOk})\n`);
      process.exit(2);
    }
    if (verifyCjs) {
      const cjsOk = verifyCjs(t.sig, t.msg, t.pk);
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
      let mutSig, mutMsg, mutPk;
      let mutatedField;
      let mutationFamily;
      let baseIdx;

      if (roll < 0.1) {
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
      } else {
        baseIdx = rng.nextUint32() % corpus.length;
        const base = corpus[baseIdx];
        mutSig = cloneBytes(base.sig);
        mutPk = cloneBytes(base.pk);
        mutMsg = cloneBytes(base.msg);

        if (roll < 0.55) {
          mutationFamily = 'sig-mutate';
          mutatedField = 'sig';
          mutSig = mutate(mutSig, rng, { hintOffset: HINT_REGION_OFFSET });
        } else if (roll < 0.775) {
          mutationFamily = 'pk-mutate';
          mutatedField = 'pk';
          mutPk = mutate(mutPk, rng);
        } else {
          mutationFamily = 'msg-mutate';
          mutatedField = 'msg';
          mutMsg = mutate(mutMsg, rng);
        }
      }

      const base = corpus[baseIdx];
      const bytesChanged =
        mutSig.length !== base.sig.length ||
        mutPk.length !== base.pk.length ||
        mutMsg.length !== base.msg.length ||
        !arraysEqual(mutSig, base.sig) ||
        !arraysEqual(mutPk, base.pk) ||
        !arraysEqual(mutMsg, base.msg);

      const t0 = performance.now();
      const src = callVerify(verifySrc, mutSig, mutMsg, mutPk);
      const mjs = callVerify(verifyMjs, mutSig, mutMsg, mutPk);
      const cjs = verifyCjs ? callVerify(verifyCjs, mutSig, mutMsg, mutPk) : null;
      const iterElapsed = performance.now() - t0;

      const srcR = src.result;
      const mjsR = mjs.result;
      const cjsR = cjs?.result ?? null;

      let diverged = false;
      if (srcR !== mjsR) diverged = true;
      if (cjsR !== null && (cjsR !== srcR || cjsR !== mjsR)) diverged = true;

      const caseMeta = {
        seed: opts.seed,
        iteration: iter,
        mutationFamily,
        mutatedField,
        baseTupleIndex: baseIdx,
        bytesChanged,
        sig: mutSig,
        msg: mutMsg,
        pk: mutPk,
        srcResult: srcR,
        mjsResult: mjsR,
        cjsResult: cjsR,
        srcError: src.error,
        mjsError: mjs.error,
        cjsError: cjs?.error ?? null,
      };

      if (diverged) {
        divergenceCount++;
        verdict.record('DIVERGENCE');
        process.stderr.write(
          `\n[!!!] DIVERGENCE at iter=${iter} family=${mutationFamily} field=${mutatedField}\n` +
            `  src=${srcR} mjs=${mjsR} cjs=${cjsR}\n`
        );
        if (budget.shouldSave('DIVERGENCE')) saveCase('DIVERGENCE', caseMeta);
      }

      if (srcR === 'threw' || mjsR === 'threw' || cjsR === 'threw') {
        // A throw shared by src and dist produces no divergence, but it is
        // still a verify-totality violation — make it count on its own.
        verdict.record('THREW');
        if (budget.shouldSave('THREW')) saveCase('THREW', caseMeta);
      }

      if (iterElapsed > opts.timeoutMs) {
        verdict.record('TIMEOUT');
        if (budget.shouldSave('TIMEOUT')) saveCase('TIMEOUT', caseMeta);
      }

      // Dist-side cryptoSignOpen parity (every 4th iteration): verify is
      // the only src↔dist-diffed entrypoint otherwise; open exercises
      // unpackSig and the signed-message parsing on the dist side too.
      if ((iter & 3) === 0) {
        const sm = new Uint8Array(mutSig.length + mutMsg.length);
        sm.set(mutSig, 0);
        sm.set(mutMsg, mutSig.length);
        const srcOpen = callOpenSerialized(openSrc, sm, mutPk);
        const mjsOpen = callOpenSerialized(openMjs, sm, mutPk);
        const cjsOpen = openCjs ? callOpenSerialized(openCjs, sm, mutPk) : null;
        if (srcOpen !== mjsOpen || (cjsOpen !== null && cjsOpen !== srcOpen)) {
          divergenceCount++;
          verdict.record('DIVERGENCE');
          process.stderr.write(
            `\n[!!!] OPEN DIVERGENCE at iter=${iter} family=${mutationFamily}\n` +
              `  src=${srcOpen.slice(0, 64)} mjs=${mjsOpen.slice(0, 64)} cjs=${cjsOpen === null ? 'n/a' : cjsOpen.slice(0, 64)}\n`
          );
          if (budget.shouldSave('OPEN_DIVERGENCE')) {
            saveCase('OPEN_DIVERGENCE', {
              ...caseMeta,
              srcResult: srcOpen.slice(0, 200),
              mjsResult: mjsOpen.slice(0, 200),
              cjsResult: cjsOpen === null ? null : cjsOpen.slice(0, 200),
            });
          }
        }
      }

      if (bytesChanged && (srcR === true || mjsR === true || cjsR === true)) {
        falseAcceptCount++;
        verdict.record('FALSE_ACCEPT');
        process.stderr.write(
          `\n[!!!] FALSE ACCEPT at iter=${iter} family=${mutationFamily} field=${mutatedField}\n` +
            `  src=${srcR} mjs=${mjsR} cjs=${cjsR} bytesChanged=${bytesChanged}\n`
        );
        if (budget.shouldSave('FALSE_ACCEPT')) saveCase('FALSE_ACCEPT', caseMeta);
      }

      if (iter > 0 && iter % 1000 === 0) {
        const elapsedSec = ((Date.now() - startTime) / 1000).toFixed(1);
        process.stderr.write(
          `[*] iter=${iter}/${opts.iterations} divergences=${divergenceCount} falseAccepts=${falseAcceptCount} elapsed=${elapsedSec}s\n`
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
  process.stderr.write(`[*] Suppressed by save budget: ${budget.suppressedCount()}\n`);
  for (const line of budget.summaryLines()) process.stderr.write(`[*]   ${line}\n`);

  process.stderr.write(`[*] Verdict:\n`);
  for (const line of verdict.summaryLines()) process.stderr.write(`[*]   ${line}\n`);

  // Single exit path: the shared severity map decides, never bespoke logic.
  process.exit(verdict.exitCode());
}

try {
  main();
} catch (e) {
  process.stderr.write(`[FATAL] ${e.stack || e.message}\n`);
  process.exit(2);
}
