#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cryptoSignKeypair, cryptoSignSignature, cryptoSignVerify } from '../src/sign.js';
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
import { SaveBudget, classifyError } from '../../../scripts/fuzz/engine/save-budget.mjs';

// Dilithium5 (Round 3): the challenge c is SeedBytes (32) long, not CTILDEBytes.
const HINT_REGION_OFFSET = SeedBytes + L * PolyZPackedBytes;

const budget = new SaveBudget();

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    seed: Date.now(),
    iterations: 100_000,
    timeoutMs: 5000,
  };
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

function cloneBytes(buf) {
  return new Uint8Array(buf);
}

function main() {
  const opts = parseArgs();
  const rng = new PRNG(opts.seed);
  const corpusDir = new URL('./corpus/verify/interesting/', import.meta.url).pathname;

  process.stderr.write(`[*] verify-src fuzzer starting (dilithium5)\n`);
  process.stderr.write(`[*] seed=${opts.seed} iterations=${opts.iterations} timeout=${opts.timeoutMs}ms\n`);
  process.stderr.write(`[*] CryptoBytes=${CryptoBytes} CryptoPublicKeyBytes=${CryptoPublicKeyBytes}\n`);
  process.stderr.write(`[*] HINT_REGION_OFFSET=${HINT_REGION_OFFSET}\n`);

  process.stderr.write(`[*] Generating 10 base corpus tuples...\n`);
  const corpus = [];
  for (let i = 0; i < 10; i++) {
    try {
      corpus.push(generateBaseTuple(opts.seed + i * 7919));
    } catch (e) {
      process.stderr.write(`[!] Failed to generate base tuple ${i}: ${e.message}\n`);
      process.exit(1);
    }
  }

  for (let i = 0; i < corpus.length; i++) {
    const t = corpus[i];
    const ok = cryptoSignVerify(t.sig, t.msg, t.pk);
    if (!ok) {
      process.stderr.write(`[!] Base tuple ${i} does not verify — corpus is broken\n`);
      process.exit(1);
    }
  }
  process.stderr.write(`[*] All 10 base tuples verify. Starting fuzz loop.\n`);

  let interestingCount = 0;
  let falseAcceptCount = 0;
  const startTime = Date.now();

  function saveCaseSync(data) {
    const name = `case_${data.iteration}_${data.mutationFamily}_${Date.now()}.json`;
    const serialized = {
      seed: data.seed,
      iteration: data.iteration,
      mutationFamily: data.mutationFamily,
      mutatedField: data.mutatedField,
      baseTupleIndex: data.baseTupleIndex,
      sig: toHex(data.sig),
      msg: toHex(data.msg),
      pk: toHex(data.pk),
      result: data.result,
      error: data.error || null,
    };
    try {
      mkdirSync(corpusDir, { recursive: true });
      writeFileSync(join(corpusDir, name), JSON.stringify(serialized, null, 2));
    } catch (e) {
      process.stderr.write(`[!] Failed to save case: ${e.message}\n`);
    }
  }

  for (let iter = 0; iter < opts.iterations; iter++) {
    try {
      const roll = rng.nextFloat();
      let mutSig, mutMsg, mutPk;
      let mutatedField;
      let mutationFamily;
      let baseIdx;

      if (roll < 0.10) {
        // Cross-splice: sig from one tuple, pk/msg from another
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
          // Mutate sig (45%)
          mutationFamily = 'sig-mutate';
          mutatedField = 'sig';
          mutSig = mutate(mutSig, rng, { hintOffset: HINT_REGION_OFFSET });
        } else if (roll < 0.775) {
          // Mutate pk (22.5%)
          mutationFamily = 'pk-mutate';
          mutatedField = 'pk';
          mutPk = mutate(mutPk, rng);
        } else {
          // Mutate msg (22.5%)
          mutationFamily = 'msg-mutate';
          mutatedField = 'msg';
          mutMsg = mutate(mutMsg, rng);
        }
      }

      let result;
      let error = null;
      let timedOut = false;
      const t0 = performance.now();

      try {
        result = cryptoSignVerify(mutSig, mutMsg, mutPk);
      } catch (e) {
        result = 'threw';
        error = e.message || String(e);
      }

      const elapsed = performance.now() - t0;
      if (elapsed > opts.timeoutMs) {
        timedOut = true;
      }

      const base = corpus[baseIdx];
      const bytesChanged =
        mutSig.length !== base.sig.length ||
        mutPk.length !== base.pk.length ||
        mutMsg.length !== base.msg.length ||
        !mutSig.every((b, i) => b === base.sig[i]) ||
        !mutPk.every((b, i) => b === base.pk[i]) ||
        !mutMsg.every((b, i) => b === base.msg[i]);

      if (result === true && bytesChanged) {
        falseAcceptCount++;
        interestingCount++;
        process.stderr.write(
          `\n[!!!] CRITICAL FALSE ACCEPT at iter=${iter} family=${mutationFamily} field=${mutatedField} baseIdx=${baseIdx}\n`
        );
        if (budget.shouldSave('FALSE_ACCEPT')) {
          saveCaseSync({
            seed: opts.seed,
            iteration: iter,
            mutationFamily,
            mutatedField,
            baseTupleIndex: baseIdx,
            sig: mutSig,
            msg: mutMsg,
            pk: mutPk,
            result: 'FALSE_ACCEPT',
            error: null,
          });
        }
      } else if (result === 'threw') {
        // cryptoSignVerify is total over malformed crypto inputs (returns
        // false) — any throw here is an unexpected finding, budget-gated
        // only to bound disk usage on a pathological run.
        interestingCount++;
        if (budget.shouldSave('THREW', classifyError(error))) {
          saveCaseSync({
            seed: opts.seed,
            iteration: iter,
            mutationFamily,
            mutatedField,
            baseTupleIndex: baseIdx,
            sig: mutSig,
            msg: mutMsg,
            pk: mutPk,
            result: 'THREW',
            error,
          });
        }
      } else if (timedOut) {
        interestingCount++;
        if (budget.shouldSave('TIMEOUT')) {
          saveCaseSync({
            seed: opts.seed,
            iteration: iter,
            mutationFamily,
            mutatedField,
            baseTupleIndex: baseIdx,
            sig: mutSig,
            msg: mutMsg,
            pk: mutPk,
            result: 'TIMEOUT',
            error: `elapsed ${elapsed.toFixed(1)}ms > ${opts.timeoutMs}ms`,
          });
        }
      }

      // Sanity check: periodically verify base tuples still pass
      if (iter > 0 && iter % 1000 === 0) {
        const checkIdx = iter % corpus.length;
        const ct = corpus[checkIdx];
        let sanity;
        try {
          sanity = cryptoSignVerify(ct.sig, ct.msg, ct.pk);
        } catch (e) {
          process.stderr.write(`[!] Sanity check THREW for base tuple ${checkIdx}: ${e.message}\n`);
          sanity = false;
        }
        if (!sanity) {
          process.stderr.write(`[!] Sanity check FAILED for base tuple ${checkIdx}\n`);
        }
      }

      if (iter > 0 && iter % 1000 === 0) {
        const now = Date.now();
        const elapsedSec = ((now - startTime) / 1000).toFixed(1);
        process.stderr.write(
          `[*] iter=${iter}/${opts.iterations} interesting=${interestingCount} falseAccepts=${falseAcceptCount} elapsed=${elapsedSec}s\n`
        );
      }
    } catch (e) {
      process.stderr.write(`[!] Fuzzer internal error at iter=${iter}: ${e.message}\n`);
    }
  }

  const totalSec = ((Date.now() - startTime) / 1000).toFixed(1);
  process.stderr.write(`\n[*] === SUMMARY ===\n`);
  process.stderr.write(`[*] Total iterations: ${opts.iterations}\n`);
  process.stderr.write(`[*] Interesting cases: ${interestingCount}\n`);
  process.stderr.write(`[*] False accepts:     ${falseAcceptCount}\n`);
  process.stderr.write(`[*] Elapsed:           ${totalSec}s\n`);
  process.stderr.write(`[*] Seed:              ${opts.seed}\n`);
  process.stderr.write(`[*] Corpus dir:        ${corpusDir}\n`);
  process.stderr.write(`[*] Suppressed by save budget: ${budget.suppressedCount()}\n`);
  for (const line of budget.summaryLines()) process.stderr.write(`[*]   ${line}\n`);

  process.exit(falseAcceptCount > 0 ? 1 : 0);
}

try {
  main();
} catch (e) {
  process.stderr.write(`[FATAL] ${e.stack || e.message}\n`);
  process.exit(2);
}
