import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { unpackSig, packSig } from '../src/packing.js';
import { cryptoSignKeypair, cryptoSignSignature, cryptoSignVerify } from '../src/sign.js';
import { PolyVecK, PolyVecL } from '../src/polyvec.js';
import {
  K, L, N, OMEGA, SeedBytes,
  CTILDEBytes, PolyZPackedBytes, PolyVecHPackedBytes,
  CryptoPublicKeyBytes, CryptoSecretKeyBytes, CryptoBytes,
} from '../src/const.js';
import { PRNG } from '../../../scripts/fuzz/engine/prng.mjs';
import { mutate } from '../../../scripts/fuzz/engine/mutate-bytes.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const args = process.argv.slice(2);
function cliArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx !== -1 && idx + 1 < args.length ? Number(args[idx + 1]) : fallback;
}

const SEED = cliArg('--seed', Date.now());
const ITERATIONS = cliArg('--iterations', 100_000);
const PER_ITER_TIMEOUT_MS = cliArg('--timeout-ms', 5000);

const hintOffset = CTILDEBytes + L * PolyZPackedBytes;
const SIG_LEN = CryptoBytes;

const SAVE_DIR = path.join(__dirname, 'corpus', 'parser', 'interesting');

function toHex(buf) {
  return Buffer.from(buf).toString('hex');
}

function saveCase(label, iter, input, detail) {
  fs.mkdirSync(SAVE_DIR, { recursive: true });
  const ts = Date.now();
  const tag = crypto.randomBytes(4).toString('hex');
  const base = `${ts}-${tag}-${label}`;

  fs.writeFileSync(path.join(SAVE_DIR, `${base}.bin`), input);

  fs.writeFileSync(path.join(SAVE_DIR, `${base}.json`), JSON.stringify({
    label,
    seed: SEED,
    iteration: iter,
    inputLen: input.length,
    inputHex: toHex(input),
    timestamp: new Date().toISOString(),
    ...detail,
  }, null, 2) + '\n');

  if (detail.originalSig) {
    fs.writeFileSync(path.join(SAVE_DIR, `${base}_orig.bin`), detail.originalSig);
  }
  if (detail.pk) {
    fs.writeFileSync(path.join(SAVE_DIR, `${base}_pk.bin`),
      typeof detail.pk === 'string' ? Buffer.from(detail.pk, 'hex') : detail.pk);
  }

  return base;
}

function generateCorpus(count, masterSeed) {
  const corpusPrng = new PRNG(masterSeed ^ 0xC0BFEED);
  const corpus = [];
  for (let i = 0; i < count; i++) {
    const pk = new Uint8Array(CryptoPublicKeyBytes);
    const sk = new Uint8Array(CryptoSecretKeyBytes);
    const keySeed = corpusPrng.nextBytes(SeedBytes);
    cryptoSignKeypair(keySeed, pk, sk);

    const msgLen = 32 + (i % 48);
    const msg = corpusPrng.nextBytes(msgLen);

    const sig = new Uint8Array(CryptoBytes);
    const ctx = new Uint8Array(0);
    cryptoSignSignature(sig, msg, sk, false, ctx);

    corpus.push({ pk, sk, msg, ctx, sig: new Uint8Array(sig), tupleIdx: i });
  }
  return corpus;
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function mutateChallengeRegion(buf, prng) {
  const out = new Uint8Array(buf);
  const flips = prng.nextRange(1, 8);
  for (let i = 0; i < flips; i++) {
    const pos = prng.nextUint32() % CTILDEBytes;
    out[pos] ^= 1 << (prng.nextUint32() % 8);
  }
  return out;
}

function mutateZRegion(buf, prng) {
  const out = new Uint8Array(buf);
  const flips = prng.nextRange(1, 12);
  for (let i = 0; i < flips; i++) {
    const pos = CTILDEBytes + (prng.nextUint32() % (hintOffset - CTILDEBytes));
    out[pos] ^= 1 << (prng.nextUint32() % 8);
  }
  return out;
}

function mutateHintRegion(buf, prng) {
  const out = new Uint8Array(buf);
  const hintLen = PolyVecHPackedBytes;
  const strategy = prng.nextUint32() % 5;

  switch (strategy) {
    case 0: {
      const row = prng.nextUint32() % K;
      const prevRow = row > 0 ? row - 1 : 0;
      const baseK = hintOffset + OMEGA + prevRow;
      const limitK = hintOffset + OMEGA + row;
      if (baseK < out.length && limitK < out.length) {
        const start = out[baseK] || 0;
        const end = out[limitK] || 0;
        if (end > start + 1) {
          const j1 = start + (prng.nextUint32() % (end - start));
          const j2 = start + (prng.nextUint32() % (end - start));
          if (j1 !== j2) {
            out[hintOffset + j1] = out[hintOffset + j2];
          }
        }
      }
      break;
    }
    case 1: {
      const row = prng.nextUint32() % K;
      const prevRow = row > 0 ? row - 1 : 0;
      const baseK = hintOffset + OMEGA + prevRow;
      const limitK = hintOffset + OMEGA + row;
      if (baseK < out.length && limitK < out.length) {
        const start = out[baseK] || 0;
        const end = out[limitK] || 0;
        if (end > start + 1) {
          for (let j = start; j < end - 1 && hintOffset + j + 1 < out.length; j++) {
            if (out[hintOffset + j] < out[hintOffset + j + 1]) {
              const tmp = out[hintOffset + j];
              out[hintOffset + j] = out[hintOffset + j + 1];
              out[hintOffset + j + 1] = tmp;
            }
          }
        }
      }
      break;
    }
    case 2: {
      const row = prng.nextUint32() % K;
      const pos = hintOffset + OMEGA + row;
      if (pos < out.length) {
        const delta = prng.nextRange(1, 20);
        out[pos] = (out[pos] + delta) & 0xFF;
      }
      break;
    }
    case 3: {
      const pos = hintOffset + OMEGA + (prng.nextUint32() % K);
      if (pos < out.length) {
        out[pos] = OMEGA + prng.nextRange(1, 180);
      }
      break;
    }
    case 4: {
      const lastCount = out[hintOffset + OMEGA + K - 1] || 0;
      for (let j = lastCount; j < OMEGA && hintOffset + j < out.length; j++) {
        out[hintOffset + j] = prng.nextRange(1, 256);
      }
      break;
    }
  }
  return out;
}

function truncateOrExtend(buf, prng) {
  const delta = prng.nextRange(-32, 33);
  const newLen = Math.max(1, buf.length + delta);
  const out = new Uint8Array(newLen);
  out.set(buf.subarray(0, Math.min(buf.length, newLen)));
  if (newLen > buf.length) {
    for (let i = buf.length; i < newLen; i++) {
      out[i] = prng.nextUint32() & 0xFF;
    }
  }
  return out;
}

function randomFullMutate(buf, prng) {
  return mutate(buf, prng);
}

function applyMutation(buf, prng) {
  const roll = prng.nextFloat();
  if (roll < 0.20) return mutateChallengeRegion(buf, prng);
  if (roll < 0.45) return mutateZRegion(buf, prng);
  if (roll < 0.80) return mutateHintRegion(buf, prng);
  if (roll < 0.90) return truncateOrExtend(buf, prng);
  return randomFullMutate(buf, prng);
}

console.log(`[unpack-sig fuzzer] mldsa87`);
console.log(`  seed=${SEED}  iterations=${ITERATIONS}`);
console.log(`  SIG_LEN=${SIG_LEN}  hintOffset=${hintOffset}  CTILDEBytes=${CTILDEBytes}`);
console.log(`  K=${K}  L=${L}  OMEGA=${OMEGA}`);
console.log(`  save_dir=${SAVE_DIR}`);
console.log();

console.log('Generating seed corpus (10 valid signatures, deterministic)...');
const corpus = generateCorpus(10, SEED);
console.log('Seed corpus ready.\n');

const prng = new PRNG(SEED);

const stats = {
  accept: 0,
  reject: 0,
  threw: 0,
  canonDrift: 0,
  falseAcceptViaParser: 0,
  nonDeterministic: 0,
  saved: 0,
};

const startTime = Date.now();

for (let iter = 0; iter < ITERATIONS; iter++) {
  const entry = corpus[prng.nextUint32() % corpus.length];
  const mutated = applyMutation(entry.sig, prng);

  const c = new Uint8Array(CTILDEBytes);
  const z = new PolyVecL();
  const h = new PolyVecK();

  const t0 = performance.now();
  let rc;
  try {
    rc = unpackSig(c, z, h, mutated);
  } catch (err) {
    stats.threw++;
    const name = saveCase('THROW', iter, mutated, {
      error: err.message,
      stack: err.stack?.split('\n').slice(0, 5).join('\n'),
      baseTupleIndex: prng.nextUint32() % corpus.length,
      originalSig: entry.sig,
      originalSigHex: toHex(entry.sig),
    });
    stats.saved++;
    if (stats.threw <= 5) {
      console.log(`  [!] THROW at iter ${iter}: ${err.message} -> ${name}`);
    }
    continue;
  }
  const iterElapsed = performance.now() - t0;

  if (rc === 0) {
    stats.accept++;

    const repacked = new Uint8Array(SIG_LEN);
    try {
      packSig(repacked, c, z, h);
    } catch (err) {
      const name = saveCase('REPACK_THROW', iter, mutated, {
        error: err.message,
        originalSig: entry.sig,
        originalSigHex: toHex(entry.sig),
      });
      stats.saved++;
      if (stats.saved <= 20) {
        console.log(`  [!] REPACK_THROW at iter ${iter}: ${err.message} -> ${name}`);
      }
      continue;
    }

    const repackSlice = repacked.subarray(0, SIG_LEN);
    const mutSlice = mutated.subarray(0, Math.min(mutated.length, SIG_LEN));
    const sameLen = mutated.length === SIG_LEN;
    if (sameLen && !arraysEqual(repackSlice, mutSlice)) {
      stats.canonDrift++;
      const name = saveCase('CANON_DRIFT', iter, mutated, {
        repackedHex: toHex(repacked),
        mutatedHex: toHex(mutated),
        originalSig: entry.sig,
        originalSigHex: toHex(entry.sig),
        diffPositions: findDiffPositions(repacked, mutated),
      });
      stats.saved++;
      console.log(`  [!!] CANONICALIZATION DRIFT at iter ${iter} -> ${name}`);
    }

    const isIdentity = mutated.length === entry.sig.length && arraysEqual(mutated, entry.sig);
    if (!isIdentity) {
      try {
        const accepted = cryptoSignVerify(mutated, entry.msg, entry.pk, entry.ctx);
        if (accepted) {
          stats.falseAcceptViaParser++;
          const diffCount = mutated.length === entry.sig.length
            ? Array.from(mutated).reduce((n, b, i) => n + (b !== entry.sig[i] ? 1 : 0), 0)
            : -1;
          const name = saveCase('FALSE_ACCEPT_VIA_PARSER', iter, mutated, {
            originalSig: entry.sig,
            originalSigHex: toHex(entry.sig),
            msg: entry.msg,
            msgHex: toHex(entry.msg),
            pk: entry.pk,
            pkHex: toHex(entry.pk),
            diffBytesFromOriginal: diffCount,
            mutatedLen: mutated.length,
            originalLen: entry.sig.length,
          });
          stats.saved++;
          console.log(`  [!!!] CRITICAL FALSE ACCEPT VIA PARSER at iter ${iter} (${diffCount} diff bytes) -> ${name}`);
        }
      } catch {
        /* verify threw on mutated sig — not a finding for this harness */
      }
    }
  } else {
    stats.reject++;
  }

  if (iter % 2000 === 0) {
    const c2 = new Uint8Array(CTILDEBytes);
    const z2 = new PolyVecL();
    const h2 = new PolyVecK();

    let rc2;
    try {
      rc2 = unpackSig(c2, z2, h2, mutated);
    } catch {
      rc2 = -1;
    }

    if (rc2 !== rc) {
      stats.nonDeterministic++;
      const name = saveCase('NON_DETERMINISTIC', iter, mutated, {
        rc1: rc, rc2,
        originalSig: entry.sig,
        originalSigHex: toHex(entry.sig),
      });
      stats.saved++;
      console.log(`  [!!] NON-DETERMINISTIC at iter ${iter}: rc1=${rc} rc2=${rc2} -> ${name}`);
    }
  }

  if (iter > 0 && iter % 10000 === 0) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const ips = (iter / (Date.now() - startTime) * 1000).toFixed(0);
    console.log(
      `  [${elapsed}s] iter=${iter}  accept=${stats.accept} reject=${stats.reject} ` +
      `threw=${stats.threw} canonDrift=${stats.canonDrift} ` +
      `falseAccept=${stats.falseAcceptViaParser} saved=${stats.saved}  (${ips} it/s)`,
    );
  }
}

const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
console.log();
console.log(`Done. ${ITERATIONS} iterations in ${elapsed}s`);
console.log(`  accept=${stats.accept}  reject=${stats.reject}  threw=${stats.threw}`);
console.log(`  canonDrift=${stats.canonDrift}  falseAcceptViaParser=${stats.falseAcceptViaParser}`);
console.log(`  nonDeterministic=${stats.nonDeterministic}  saved=${stats.saved}`);

if (stats.falseAcceptViaParser > 0) {
  console.log('\n  *** CRITICAL: False accepts via parser detected! ***');
  process.exit(2);
}
if (stats.canonDrift > 0) {
  console.log('\n  *** WARNING: Canonicalization drift detected ***');
  process.exit(1);
}

process.exit(0);

function findDiffPositions(a, b) {
  const diffs = [];
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len && diffs.length < 20; i++) {
    const va = i < a.length ? a[i] : -1;
    const vb = i < b.length ? b[i] : -1;
    if (va !== vb) {
      diffs.push({ pos: i, repacked: va, mutated: vb });
    }
  }
  return diffs;
}
