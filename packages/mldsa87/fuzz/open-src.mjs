#!/usr/bin/env node
/**
 * Fuzz harness for cryptoSignOpen() — mldsa87
 *
 * Generates mutated signed-message / public-key pairs and feeds them to
 * cryptoSignOpen(), looking for forgery accepts or unexpected crashes.
 *
 * Usage:
 *   node packages/mldsa87/fuzz/open-src.mjs [--seed N] [--iterations N] [--timeout-ms N]
 */

import { cryptoSignKeypair, cryptoSign, cryptoSignOpen } from '../src/sign.js';
import { CryptoPublicKeyBytes, CryptoSecretKeyBytes, CryptoBytes } from '../src/const.js';
import { PRNG } from '../../../scripts/fuzz/engine/prng.mjs';
import { mutate } from '../../../scripts/fuzz/engine/mutate-bytes.mjs';

import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, 'corpus', 'open', 'interesting');

const { values: cli } = parseArgs({
  options: {
    seed:          { type: 'string', default: String(Date.now()) },
    iterations:    { type: 'string', default: '100000' },
    'timeout-ms':  { type: 'string', default: '5000' },
  },
  strict: false,
});

const SEED       = Number(cli.seed);
const ITERATIONS = Number(cli.iterations);
const PER_ITER_TIMEOUT_MS = Number(cli['timeout-ms']);

const prng = new PRNG(SEED);

const stats = {
  iterations: 0,
  rejected: 0,
  threw: 0,
  interestingSaved: 0,
  criticals: 0,
  sanityChecks: 0,
  sanityFails: 0,
  stratCounts: new Array(6).fill(0),
};

function ensureDir(dir) {
  try { mkdirSync(dir, { recursive: true }); } catch { /* exists */ }
}

function saveCase(tag, iter, data) {
  ensureDir(CORPUS_DIR);
  const ts = Date.now();
  const base = `${tag}_iter${iter}_${ts}`;
  const jsonPath = join(CORPUS_DIR, `${base}.json`);

  const serialized = {};
  for (const [k, v] of Object.entries(data)) {
    serialized[k] = v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v;
  }

  writeFileSync(jsonPath, JSON.stringify(serialized, null, 2));

  if (data.sm instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_sm.bin`), data.sm);
  }
  if (data.pk instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_pk.bin`), data.pk);
  }
  if (data.originalSm instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_orig_sm.bin`), data.originalSm);
  }
  if (data.originalPk instanceof Uint8Array) {
    writeFileSync(join(CORPUS_DIR, `${base}_orig_pk.bin`), data.originalPk);
  }

  return `${base}.json`;
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Corpus generation
// ---------------------------------------------------------------------------
const CORPUS_SIZE = 10;
const corpus = [];

console.log(`[open-src] seed=${SEED} iterations=${ITERATIONS} per-iter-timeout=${PER_ITER_TIMEOUT_MS}ms`);
console.log(`[open-src] CryptoBytes=${CryptoBytes} CryptoPublicKeyBytes=${CryptoPublicKeyBytes}`);
console.log('[open-src] generating base corpus …');

for (let i = 0; i < CORPUS_SIZE; i++) {
  const seed = prng.nextBytes(32);
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  cryptoSignKeypair(seed, pk, sk);

  const msgLen = prng.nextRange(1, 128);
  const msg = prng.nextBytes(msgLen);
  const ctx = new Uint8Array(0);
  const sm = cryptoSign(msg, sk, false, ctx);

  const opened = cryptoSignOpen(sm, pk, ctx);
  if (!opened || !arraysEqual(opened, msg)) {
    console.error(`[open-src] FATAL: corpus sanity failed for tuple ${i}`);
    process.exit(1);
  }

  corpus.push({ pk, sk, sm, msg, ctx });
}

console.log(`[open-src] corpus ready (${corpus.length} tuples)`);

// ---------------------------------------------------------------------------
// Mutation strategies
// ---------------------------------------------------------------------------

function corruptSigPrefix(sm, rng) {
  const out = new Uint8Array(sm);
  const region = out.subarray(0, CryptoBytes);
  const mutated = mutate(region, rng);
  const result = new Uint8Array(sm.length - CryptoBytes + mutated.length);
  result.set(mutated, 0);
  result.set(sm.subarray(CryptoBytes), mutated.length);
  return result;
}

function corruptMsgSuffix(sm, rng) {
  const out = new Uint8Array(sm);
  if (sm.length <= CryptoBytes) return mutate(out, rng);
  const msgPart = out.subarray(CryptoBytes);
  const mutated = mutate(msgPart, rng);
  const result = new Uint8Array(CryptoBytes + mutated.length);
  result.set(sm.subarray(0, CryptoBytes), 0);
  result.set(mutated, CryptoBytes);
  return result;
}

function corruptBoundary(sm, rng) {
  const out = new Uint8Array(sm);
  const start = Math.max(0, CryptoBytes - 16);
  const end = Math.min(out.length, CryptoBytes + 16);
  for (let i = start; i < end; i++) {
    if (rng.nextFloat() < 0.4) {
      out[i] = rng.nextUint32() & 0xFF;
    }
  }
  return out;
}

function truncateNearBoundary(sm, rng) {
  const offset = rng.nextRange(-32, 33);
  const newLen = Math.max(0, CryptoBytes + offset);
  const out = new Uint8Array(newLen);
  out.set(sm.subarray(0, Math.min(sm.length, newLen)));
  return out;
}

function mutatePk(pk, rng) {
  return mutate(pk, rng);
}

function extendTrailing(sm, rng) {
  const extra = rng.nextRange(1, 64);
  const out = new Uint8Array(sm.length + extra);
  out.set(sm, 0);
  const tail = rng.nextBytes(extra);
  out.set(tail, sm.length);
  return out;
}

const STRATEGIES = [
  { weight: 30, name: 'sig-prefix',    fn: (sm, _pk, rng) => [corruptSigPrefix(sm, rng), null] },
  { weight: 30, name: 'msg-suffix',    fn: (sm, _pk, rng) => [corruptMsgSuffix(sm, rng), null] },
  { weight: 15, name: 'boundary',      fn: (sm, _pk, rng) => [corruptBoundary(sm, rng), null] },
  { weight: 10, name: 'truncate',      fn: (sm, _pk, rng) => [truncateNearBoundary(sm, rng), null] },
  { weight: 10, name: 'corrupt-pk',    fn: (sm, pk, rng)  => [new Uint8Array(sm), mutatePk(pk, rng)] },
  { weight: 5,  name: 'extend-trail',  fn: (sm, _pk, rng) => [extendTrailing(sm, rng), null] },
];
const TOTAL_WEIGHT = STRATEGIES.reduce((s, st) => s + st.weight, 0);

function pickStrategy(rng) {
  let r = rng.nextUint32() % TOTAL_WEIGHT;
  for (let i = 0; i < STRATEGIES.length; i++) {
    if (r < STRATEGIES[i].weight) return i;
    r -= STRATEGIES[i].weight;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------
const startTime = Date.now();

for (let iter = 0; iter < ITERATIONS; iter++) {
  stats.iterations = iter + 1;
  const tupleIdx = prng.nextUint32() % corpus.length;
  const tuple = corpus[tupleIdx];
  const stratIdx = pickStrategy(prng);
  stats.stratCounts[stratIdx]++;
  const strat = STRATEGIES[stratIdx];

  const [mutSm, mutPk] = strat.fn(tuple.sm, tuple.pk, prng);
  const usePk = mutPk ?? tuple.pk;

  const smChanged = mutSm.length !== tuple.sm.length || !arraysEqual(mutSm, tuple.sm);
  const pkChanged = mutPk !== null && (mutPk.length !== tuple.pk.length || !arraysEqual(mutPk, tuple.pk));
  const inputMutated = smChanged || pkChanged;

  let result;
  let threw = false;
  let threwMsg = '';
  const t0 = performance.now();
  try {
    result = cryptoSignOpen(mutSm, usePk, tuple.ctx);
  } catch (e) {
    threw = true;
    threwMsg = e?.message ?? String(e);
    stats.threw++;
  }
  const iterElapsed = performance.now() - t0;
  const timedOut = iterElapsed > PER_ITER_TIMEOUT_MS;

  const caseMeta = {
    seed: SEED,
    iteration: iter,
    strategy: strat.name,
    baseTupleIndex: tupleIdx,
    smChanged,
    pkChanged,
    elapsedMs: iterElapsed.toFixed(2),
    sm: mutSm,
    pk: usePk,
    originalSm: tuple.sm,
    originalPk: tuple.pk,
    originalMsg: tuple.msg,
  };

  if (timedOut) {
    stats.interestingSaved++;
    const name = saveCase('TIMEOUT', iter, {
      ...caseMeta,
      result: String(result ?? 'pending'),
      error: `elapsed ${iterElapsed.toFixed(1)}ms > ${PER_ITER_TIMEOUT_MS}ms`,
    });
    console.log(`[open-src] TIMEOUT @${iter} [${strat.name}] ${iterElapsed.toFixed(0)}ms -> ${name}`);
    continue;
  }

  if (threw) {
    const name = saveCase('throw', iter, { ...caseMeta, error: threwMsg });
    stats.interestingSaved++;
    console.log(`[open-src] THROW @${iter} [${strat.name}]: ${threwMsg} -> ${name}`);
    continue;
  }

  if (result !== undefined && inputMutated) {
    if (result instanceof Uint8Array && !arraysEqual(result, tuple.msg)) {
      stats.criticals++;
      const name = saveCase('CRITICAL', iter, {
        ...caseMeta,
        openedMsg: result,
        expectedMsg: tuple.msg,
      });
      stats.interestingSaved++;
      console.log(`[open-src] *** CRITICAL FORGERY @${iter} [${strat.name}] -> ${name}`);
    } else if (result instanceof Uint8Array && arraysEqual(result, tuple.msg)) {
      const name = saveCase('accept_same_msg', iter, {
        ...caseMeta,
        openedMsg: result,
      });
      stats.interestingSaved++;
      console.log(`[open-src] INTERESTING accept (same msg) @${iter} [${strat.name}] -> ${name}`);
    }
    continue;
  }

  if (result === undefined) {
    stats.rejected++;
  }

  if ((iter + 1) % 500 === 0) {
    const check = prng.pick(corpus);
    stats.sanityChecks++;
    try {
      const opened = cryptoSignOpen(check.sm, check.pk, check.ctx);
      if (!opened || !arraysEqual(opened, check.msg)) {
        stats.sanityFails++;
        console.error(`[open-src] SANITY FAIL @${iter}: valid tuple did not open`);
      }
    } catch (e) {
      stats.sanityFails++;
      console.error(`[open-src] SANITY THROW @${iter}: ${e?.message}`);
    }
  }

  if ((iter + 1) % 1000 === 0) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const rate = ((iter + 1) / (Date.now() - startTime) * 1000).toFixed(0);
    console.log(
      `[open-src] ${iter + 1}/${ITERATIONS} (${elapsed}s, ${rate} it/s) ` +
      `rejected=${stats.rejected} threw=${stats.threw} saved=${stats.interestingSaved} ` +
      `criticals=${stats.criticals} sanity=${stats.sanityChecks}/${stats.sanityChecks - stats.sanityFails}ok`,
    );
  }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
console.log('\n===== FUZZ SUMMARY =====');
console.log(`Seed:         ${SEED}`);
console.log(`Iterations:   ${stats.iterations}`);
console.log(`Elapsed:      ${elapsed}s`);
console.log(`Rate:         ${(stats.iterations / (Date.now() - startTime) * 1000).toFixed(0)} it/s`);
console.log(`Rejected:     ${stats.rejected}`);
console.log(`Threw:        ${stats.threw}`);
console.log(`Saved:        ${stats.interestingSaved}`);
console.log(`Criticals:    ${stats.criticals}`);
console.log(`Sanity:       ${stats.sanityChecks} checks, ${stats.sanityFails} failures`);
console.log('Strategy distribution:');
for (let i = 0; i < STRATEGIES.length; i++) {
  console.log(`  ${STRATEGIES[i].name.padEnd(14)} ${stats.stratCounts[i]}`);
}
console.log(`Corpus dir:   ${CORPUS_DIR}`);
console.log('========================\n');

if (stats.criticals > 0) {
  console.error(`[open-src] CRITICAL: ${stats.criticals} forgery case(s) found!`);
  process.exit(2);
}
if (stats.sanityFails > 0) {
  console.error(`[open-src] WARNING: ${stats.sanityFails} sanity failure(s)`);
  process.exit(3);
}

process.exit(0);
