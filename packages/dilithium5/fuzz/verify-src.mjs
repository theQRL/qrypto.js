#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
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
import { Verdict } from '../../../scripts/fuzz/engine/verdict.mjs';

// Dilithium5 (Round 3): the challenge c is SeedBytes (32) long, not CTILDEBytes.
const HINT_REGION_OFFSET = SeedBytes + L * PolyZPackedBytes;

const budget = new SaveBudget();
const verdict = new Verdict();

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

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function main() {
  const opts = parseArgs();
  const rng = new PRNG(opts.seed);
  const corpusDir = join(dirname(fileURLToPath(import.meta.url)), 'corpus', 'verify', 'interesting');

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
      process.exit(2);
    }
  }

  for (let i = 0; i < corpus.length; i++) {
    const t = corpus[i];
    const ok = cryptoSignVerify(t.sig, t.msg, t.pk);
    if (!ok) {
      process.stderr.write(`[!] Base tuple ${i} does not verify — corpus is broken\n`);
      process.exit(2);
    }
  }
  process.stderr.write(`[*] All 10 base tuples verify. Starting fuzz loop.\n`);

  let interestingCount = 0;
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
      msg: data.msg instanceof Uint8Array ? toHex(data.msg) : String(data.msg),
      msgIsString: typeof data.msg === 'string',
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
      // What the documented contract says this iteration's inputs must do:
      // 'accept' (semantically unchanged) or 'reject' (mutated / malformed).
      // Dilithium5 has no ctx parameter, so there is no 'throw' family here.
      let expectation = 'reject';

      if (roll < 0.1) {
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

        if (roll < 0.5) {
          // Mutate sig (40%)
          mutationFamily = 'sig-mutate';
          mutatedField = 'sig';
          mutSig = mutate(mutSig, rng, { hintOffset: HINT_REGION_OFFSET });
        } else if (roll < 0.7) {
          // Mutate pk (20%)
          mutationFamily = 'pk-mutate';
          mutatedField = 'pk';
          mutPk = mutate(mutPk, rng);
        } else if (roll < 0.9) {
          // Mutate msg bytes (20%)
          mutationFamily = 'msg-mutate';
          mutatedField = 'msg';
          mutMsg = mutate(mutMsg, rng);
        } else {
          // Hex-string message path (10%): exercise messageToBytes — the
          // attacker-facing string branch no byte-level family reaches.
          mutationFamily = 'msg-hex';
          mutatedField = 'msg';
          const sub = rng.nextFloat();
          const sameHex = toHex(base.msg);
          if (sub < 0.25) {
            // Valid hex of the SAME message (optionally 0x-prefixed):
            // semantically unchanged, must still verify.
            mutMsg = rng.nextFloat() < 0.5 ? `0x${sameHex}` : sameHex;
            expectation = 'accept';
          } else if (sub < 0.5) {
            // Valid hex of a mutated message: must reject.
            mutMsg = toHex(mutate(cloneBytes(base.msg), rng));
          } else if (sub < 0.65) {
            // Odd-length hex: strict parser must reject.
            mutMsg = sameHex.slice(0, sameHex.length - 1) || 'a';
          } else if (sub < 0.8) {
            // Non-hex characters injected.
            const pos = rng.nextUint32() % Math.max(1, sameHex.length);
            mutMsg = `${sameHex.slice(0, pos)}zq${sameHex.slice(pos + 2)}`;
          } else if (sub < 0.9) {
            // Embedded whitespace (documented as not accepted).
            const pos = rng.nextUint32() % Math.max(1, sameHex.length);
            mutMsg = `${sameHex.slice(0, pos)} ${sameHex.slice(pos)}`;
          } else {
            // Not hex at all.
            mutMsg = 'not hex input!';
          }
        }
      }

      // For byte-level families, "semantically unchanged" is plain byte
      // equality against the base tuple (mutators can no-op by chance).
      if (expectation === 'reject' && mutMsg instanceof Uint8Array) {
        const base = corpus[baseIdx];
        const bytesChanged =
          !bytesEqual(mutSig, base.sig) || !bytesEqual(mutPk, base.pk) || !bytesEqual(mutMsg, base.msg);
        if (!bytesChanged) expectation = 'accept';
      }

      let result;
      let error = null;
      const t0 = performance.now();
      try {
        result = cryptoSignVerify(mutSig, mutMsg, mutPk);
      } catch (e) {
        result = 'threw';
        error = e.message || String(e);
      }
      const elapsed = performance.now() - t0;
      const timedOut = elapsed > opts.timeoutMs;

      const caseMeta = {
        seed: opts.seed,
        iteration: iter,
        mutationFamily,
        mutatedField,
        baseTupleIndex: baseIdx,
        sig: mutSig,
        msg: mutMsg,
        pk: mutPk,
      };

      if (result === 'threw') {
        // cryptoSignVerify is total over malformed crypto inputs (returns
        // false) — any throw is an unexpected finding, budget-gated only
        // to bound disk usage on a pathological run.
        verdict.record('THREW');
        interestingCount++;
        if (budget.shouldSave('THREW', classifyError(error))) {
          saveCaseSync({ ...caseMeta, result: 'THREW', error });
        }
      } else if (result === true && expectation === 'reject') {
        verdict.record('FALSE_ACCEPT');
        interestingCount++;
        process.stderr.write(
          `\n[!!!] CRITICAL FALSE ACCEPT at iter=${iter} family=${mutationFamily} field=${mutatedField} baseIdx=${baseIdx}\n`
        );
        if (budget.shouldSave('FALSE_ACCEPT')) {
          saveCaseSync({ ...caseMeta, result: 'FALSE_ACCEPT', error: null });
        }
      } else if (result === false && expectation === 'accept') {
        // A semantically unchanged input stopped verifying — the same
        // soundness class as a failed base-tuple sanity check.
        verdict.record('SANITY_FAIL');
        interestingCount++;
        process.stderr.write(
          `\n[!!!] SANITY FAIL at iter=${iter} family=${mutationFamily}: semantically unchanged input rejected\n`
        );
        if (budget.shouldSave('SANITY_FAIL')) {
          saveCaseSync({ ...caseMeta, result: 'SANITY_FAIL', error: null });
        }
      }

      if (timedOut) {
        verdict.record('TIMEOUT');
        interestingCount++;
        if (budget.shouldSave('TIMEOUT')) {
          saveCaseSync({
            ...caseMeta,
            result: 'TIMEOUT',
            error: `elapsed ${elapsed.toFixed(1)}ms > ${opts.timeoutMs}ms`,
          });
        }
      }

      // Sanity check: periodically re-verify base tuples, rotating through
      // the whole corpus (iter/1000 mod len — `iter % len` is constant 0
      // when the corpus size divides the cadence).
      if (iter > 0 && iter % 1000 === 0) {
        const checkIdx = Math.floor(iter / 1000) % corpus.length;
        const ct = corpus[checkIdx];
        let sanity;
        try {
          sanity = cryptoSignVerify(ct.sig, ct.msg, ct.pk);
        } catch (e) {
          process.stderr.write(`[!] Sanity check THREW for base tuple ${checkIdx}: ${e.message}\n`);
          sanity = false;
        }
        if (!sanity) {
          verdict.record('SANITY_FAIL');
          process.stderr.write(`[!] Sanity check FAILED for base tuple ${checkIdx}\n`);
        }

        const now = Date.now();
        const elapsedSec = ((now - startTime) / 1000).toFixed(1);
        process.stderr.write(
          `[*] iter=${iter}/${opts.iterations} interesting=${interestingCount} falseAccepts=${verdict.count('FALSE_ACCEPT')} elapsed=${elapsedSec}s\n`
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
  process.stderr.write(`[*] False accepts:     ${verdict.count('FALSE_ACCEPT')}\n`);
  process.stderr.write(`[*] Elapsed:           ${totalSec}s\n`);
  process.stderr.write(`[*] Seed:              ${opts.seed}\n`);
  process.stderr.write(`[*] Corpus dir:        ${corpusDir}\n`);
  process.stderr.write(`[*] Verdict:\n`);
  for (const line of verdict.summaryLines()) process.stderr.write(`[*]   ${line}\n`);
  process.stderr.write(`[*] Suppressed by save budget: ${budget.suppressedCount()}\n`);
  for (const line of budget.summaryLines()) process.stderr.write(`[*]   ${line}\n`);

  // Single exit path: the shared severity map decides, never bespoke logic.
  process.exit(verdict.exitCode());
}

try {
  main();
} catch (e) {
  process.stderr.write(`[FATAL] ${e.stack || e.message}\n`);
  process.exit(2);
}
