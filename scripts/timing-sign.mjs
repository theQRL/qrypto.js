#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const TARGETS = {
  mldsa87: 'packages/mldsa87/src/index.js',
  dilithium5: 'packages/dilithium5/src/index.js',
};

const PROFILES = {
  quick: {
    keyCount: 12,
    samplesPerKey: 5,
    warmupPerKey: 3,
    sameKeySamples: 40,
    messageLength: 32,
  },
  standard: {
    keyCount: 24,
    samplesPerKey: 9,
    warmupPerKey: 5,
    sameKeySamples: 80,
    messageLength: 32,
  },
  deep: {
    keyCount: 40,
    samplesPerKey: 15,
    warmupPerKey: 8,
    sameKeySamples: 160,
    messageLength: 32,
  },
  isolated: {
    keyCount: 32,
    samplesPerKey: 15,
    warmupPerKey: 8,
    sameKeySamples: 40,
    messageLength: 32,
  },
};

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    target: 'both',
    profile: 'quick',
    keyCount: null,
    samplesPerKey: null,
    warmupPerKey: null,
    sameKeySamples: null,
    messageLength: null,
    includeRaw: false,
    crossKeyMode: 'sequential',
    skipSameKey: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--target' && i + 1 < args.length) opts.target = args[++i];
    else if (arg === '--profile' && i + 1 < args.length) opts.profile = args[++i];
    else if (arg === '--keys' && i + 1 < args.length) opts.keyCount = Number(args[++i]);
    else if (arg === '--samples-per-key' && i + 1 < args.length) opts.samplesPerKey = Number(args[++i]);
    else if (arg === '--warmup-per-key' && i + 1 < args.length) opts.warmupPerKey = Number(args[++i]);
    else if (arg === '--same-key-samples' && i + 1 < args.length) opts.sameKeySamples = Number(args[++i]);
    else if (arg === '--message-length' && i + 1 < args.length) opts.messageLength = Number(args[++i]);
    else if (arg === '--include-raw') opts.includeRaw = true;
    else if (arg === '--cross-key-mode' && i + 1 < args.length) opts.crossKeyMode = args[++i];
    else if (arg === '--skip-same-key') opts.skipSameKey = true;
    else if (arg === '--help') {
      printHelp();
      process.exit(0);
    }
  }

  return opts;
}

function printHelp() {
  console.log(`Usage: node scripts/timing-sign.mjs [options]

Options:
  --target <mldsa87|dilithium5|both>   package(s) to measure (default: both)
  --profile <quick|standard|deep|isolated>
                                       measurement profile (default: quick)
  --keys <n>                           override key count
  --samples-per-key <n>                override measured runs per key
  --warmup-per-key <n>                 override warmup runs per key
  --same-key-samples <n>               override repeated same-key samples
  --message-length <n>                 fixed message length in bytes
  --include-raw                        include raw nanosecond samples in JSON output
  --cross-key-mode <sequential|round-robin>
                                       cross-key measurement order (default: sequential)
  --skip-same-key                      skip same-key scenarios and measure only cross-key timing
  --help                               show this message
`);
}

function resolveTargets(target) {
  if (target === 'both') return ['mldsa87', 'dilithium5'];
  if (!TARGETS[target]) {
    throw new Error(`unknown target "${target}"`);
  }
  return [target];
}

function resolveConfig(opts) {
  const base = PROFILES[opts.profile];
  if (!base) {
    throw new Error(`unknown profile "${opts.profile}"`);
  }
  const cfg = {
    keyCount: opts.keyCount ?? base.keyCount,
    samplesPerKey: opts.samplesPerKey ?? base.samplesPerKey,
    warmupPerKey: opts.warmupPerKey ?? base.warmupPerKey,
    sameKeySamples: opts.sameKeySamples ?? base.sameKeySamples,
    messageLength: opts.messageLength ?? base.messageLength,
    includeRaw: opts.includeRaw,
    crossKeyMode: opts.crossKeyMode,
    skipSameKey: opts.skipSameKey,
  };

  for (const [k, v] of Object.entries(cfg)) {
    if (k === 'includeRaw' || k === 'crossKeyMode' || k === 'skipSameKey') continue;
    if (!Number.isSafeInteger(v) || v <= 0) {
      throw new Error(`invalid ${k}: ${v}`);
    }
  }

  if (!new Set(['sequential', 'round-robin']).has(cfg.crossKeyMode)) {
    throw new Error(`invalid crossKeyMode: ${cfg.crossKeyMode}`);
  }

  return cfg;
}

function nowNs() {
  return process.hrtime.bigint();
}

function durationNs(fn) {
  const start = nowNs();
  fn();
  return Number(nowNs() - start);
}

function round(value, digits = 3) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function nsToUs(ns) {
  return round(ns / 1000, 3);
}

function mean(values) {
  return values.reduce((acc, value) => acc + value, 0) / values.length;
}

function percentileSorted(values, p) {
  if (values.length === 1) return values[0];
  const idx = (values.length - 1) * p;
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return values[lo];
  const fraction = idx - lo;
  return values[lo] + (values[hi] - values[lo]) * fraction;
}

function summarizeNs(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const avg = mean(sorted);
  const variance = mean(sorted.map((value) => (value - avg) ** 2));
  const med = percentileSorted(sorted, 0.5);
  const deviations = sorted.map((value) => Math.abs(value - med)).sort((a, b) => a - b);

  return {
    count: sorted.length,
    minUs: nsToUs(sorted[0]),
    p10Us: nsToUs(percentileSorted(sorted, 0.1)),
    p50Us: nsToUs(med),
    p90Us: nsToUs(percentileSorted(sorted, 0.9)),
    p95Us: nsToUs(percentileSorted(sorted, 0.95)),
    maxUs: nsToUs(sorted[sorted.length - 1]),
    meanUs: nsToUs(avg),
    sdUs: nsToUs(Math.sqrt(variance)),
    madUs: nsToUs(percentileSorted(deviations, 0.5)),
  };
}

function clockProbe(iterations = 10_000) {
  const diffs = [];
  for (let i = 0; i < iterations; i++) {
    const start = nowNs();
    diffs.push(Number(nowNs() - start));
  }
  return summarizeNs(diffs);
}

function seedFromIndex(index) {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    seed[i] = (index * 131 + i * 17 + 29) & 0xff;
  }
  return seed;
}

function messageFromIndex(length, index) {
  const message = new Uint8Array(length);
  for (let i = 0; i < message.length; i++) {
    message[i] = (index * 73 + i * 19 + 7) & 0xff;
  }
  return message;
}

async function loadTarget(name) {
  const mod = await import(pathToFileURL(join(ROOT, TARGETS[name])).href);
  return { name, mod };
}

function makeKeypair(mod, seed) {
  const pk = new Uint8Array(mod.CryptoPublicKeyBytes);
  const sk = new Uint8Array(mod.CryptoSecretKeyBytes);
  mod.cryptoSignKeypair(seed, pk, sk);
  return { pk, sk };
}

const EMPTY_CTX = new Uint8Array(0);

function signOnce(mod, sig, message, sk, randomizedSigning, targetName) {
  if (targetName === 'mldsa87') {
    mod.cryptoSignSignature(sig, message, sk, randomizedSigning, EMPTY_CTX);
  } else {
    mod.cryptoSignSignature(sig, message, sk, randomizedSigning);
  }
}

function initCrossKeyEntries(mod, cfg) {
  const entries = [];
  for (let keyIndex = 0; keyIndex < cfg.keyCount; keyIndex++) {
    const seed = seedFromIndex(keyIndex + 1);
    const { sk } = makeKeypair(mod, seed);
    entries.push({
      keyIndex,
      seedPreviewHex: Buffer.from(seed.slice(0, 8)).toString('hex'),
      sk,
      sig: new Uint8Array(mod.CryptoBytes),
      samplesNs: [],
    });
  }
  return entries;
}

function roundRobinOrder(count, round) {
  const offset = round % count;
  const order = [];
  if (round % 2 === 0) {
    for (let i = 0; i < count; i++) {
      order.push((offset + i) % count);
    }
  } else {
    for (let i = count - 1; i >= 0; i--) {
      order.push((offset + i) % count);
    }
  }
  return order;
}

function finalizeCrossKey(entries, cfg, metadata) {
  const perKeyMedianNs = [];
  const perKey = entries.map((entry) => {
    const stats = summarizeNs(entry.samplesNs);
    const medianNs = percentileSorted([...entry.samplesNs].sort((a, b) => a - b), 0.5);
    perKeyMedianNs.push(medianNs);
    return {
      keyIndex: entry.keyIndex,
      seedPreviewHex: entry.seedPreviewHex,
      stats,
      ...(cfg.includeRaw ? { rawNs: entry.samplesNs } : {}),
    };
  });

  const sortedByMedian = [...perKey].sort((a, b) => a.stats.p50Us - b.stats.p50Us);
  const fastest = sortedByMedian.slice(0, Math.min(3, sortedByMedian.length));
  const slowest = sortedByMedian.slice(-Math.min(3, sortedByMedian.length)).reverse();

  return {
    keyCount: cfg.keyCount,
    samplesPerKey: cfg.samplesPerKey,
    warmupPerKey: cfg.warmupPerKey,
    mode: metadata.mode,
    ...(metadata.orderPreview ? { orderPreview: metadata.orderPreview } : {}),
    medianSummary: summarizeNs(perKeyMedianNs),
    fastestMedianUs: fastest[0].stats.p50Us,
    slowestMedianUs: slowest[0].stats.p50Us,
    slowestToFastestRatio: round(slowest[0].stats.p50Us / fastest[0].stats.p50Us, 3),
    fastestKeys: fastest.map((entry) => ({
      keyIndex: entry.keyIndex,
      seedPreviewHex: entry.seedPreviewHex,
      medianUs: entry.stats.p50Us,
      p90Us: entry.stats.p90Us,
    })),
    slowestKeys: slowest.map((entry) => ({
      keyIndex: entry.keyIndex,
      seedPreviewHex: entry.seedPreviewHex,
      medianUs: entry.stats.p50Us,
      p90Us: entry.stats.p90Us,
    })),
    perKey,
  };
}

function measureSameKeyScenarios(mod, cfg, targetName) {
  const seed = seedFromIndex(0);
  const { sk } = makeKeypair(mod, seed);
  const sig = new Uint8Array(mod.CryptoBytes);
  const fixedMessage = messageFromIndex(cfg.messageLength, 0);

  for (let i = 0; i < cfg.warmupPerKey; i++) {
    signOnce(mod, sig, fixedMessage, sk, false, targetName);
    signOnce(mod, sig, fixedMessage, sk, true, targetName);
  }

  const fixedDeterministicNs = [];
  const varyingDeterministicNs = [];
  const fixedRandomizedNs = [];

  for (let i = 0; i < cfg.sameKeySamples; i++) {
    fixedDeterministicNs.push(durationNs(() => signOnce(mod, sig, fixedMessage, sk, false, targetName)));
  }

  for (let i = 0; i < cfg.sameKeySamples; i++) {
    const message = messageFromIndex(cfg.messageLength, i + 1);
    varyingDeterministicNs.push(durationNs(() => signOnce(mod, sig, message, sk, false, targetName)));
  }

  for (let i = 0; i < cfg.sameKeySamples; i++) {
    fixedRandomizedNs.push(durationNs(() => signOnce(mod, sig, fixedMessage, sk, true, targetName)));
  }

  const fixedSummary = summarizeNs(fixedDeterministicNs);
  const varyingSummary = summarizeNs(varyingDeterministicNs);
  const randomizedSummary = summarizeNs(fixedRandomizedNs);

  const result = {
    fixedDeterministic: fixedSummary,
    varyingMessageDeterministic: varyingSummary,
    fixedRandomized: randomizedSummary,
    ratios: {
      varyingVsFixedP50: round(varyingSummary.p50Us / fixedSummary.p50Us, 3),
      randomizedVsFixedP50: round(randomizedSummary.p50Us / fixedSummary.p50Us, 3),
    },
  };

  if (cfg.includeRaw) {
    result.rawNs = {
      fixedDeterministic: fixedDeterministicNs,
      varyingMessageDeterministic: varyingDeterministicNs,
      fixedRandomized: fixedRandomizedNs,
    };
  }

  return result;
}

function measureCrossKeyDeterministicSequential(mod, cfg, targetName) {
  const message = messageFromIndex(cfg.messageLength, 999);
  const entries = initCrossKeyEntries(mod, cfg);
  for (const entry of entries) {
    for (let i = 0; i < cfg.warmupPerKey; i++) {
      signOnce(mod, entry.sig, message, entry.sk, false, targetName);
    }

    const samplesNs = [];
    for (let i = 0; i < cfg.samplesPerKey; i++) {
      samplesNs.push(durationNs(() => signOnce(mod, entry.sig, message, entry.sk, false, targetName)));
    }
    entry.samplesNs = samplesNs;
  }

  return finalizeCrossKey(entries, cfg, { mode: 'sequential' });
}

function measureCrossKeyDeterministicRoundRobin(mod, cfg, targetName) {
  const message = messageFromIndex(cfg.messageLength, 999);
  const entries = initCrossKeyEntries(mod, cfg);

  for (let round = 0; round < cfg.warmupPerKey; round++) {
    const order = roundRobinOrder(entries.length, round);
    for (const idx of order) {
      signOnce(mod, entries[idx].sig, message, entries[idx].sk, false, targetName);
    }
  }

  const orderPreview = [];
  for (let round = 0; round < cfg.samplesPerKey; round++) {
    const order = roundRobinOrder(entries.length, round);
    if (round < 3) orderPreview.push(order);
    for (const idx of order) {
      entries[idx].samplesNs.push(
        durationNs(() => signOnce(mod, entries[idx].sig, message, entries[idx].sk, false, targetName)),
      );
    }
  }

  return finalizeCrossKey(entries, cfg, { mode: 'round-robin', orderPreview });
}

function measureCrossKeyDeterministic(mod, cfg, targetName) {
  if (cfg.crossKeyMode === 'round-robin') {
    return measureCrossKeyDeterministicRoundRobin(mod, cfg, targetName);
  }
  return measureCrossKeyDeterministicSequential(mod, cfg, targetName);
}

function printTargetSummary(name, result) {
  console.log(`\n== ${name} ==`);
  if (result.sameKey) {
    console.log(
      `same-key fixed deterministic p50=${result.sameKey.fixedDeterministic.p50Us}us ` +
      `p95=${result.sameKey.fixedDeterministic.p95Us}us`,
    );
    console.log(
      `same-key varying deterministic p50=${result.sameKey.varyingMessageDeterministic.p50Us}us ` +
      `ratio=${result.sameKey.ratios.varyingVsFixedP50}x`,
    );
    console.log(
      `same-key fixed randomized p50=${result.sameKey.fixedRandomized.p50Us}us ` +
      `ratio=${result.sameKey.ratios.randomizedVsFixedP50}x`,
    );
  } else {
    console.log('same-key scenarios skipped');
  }
  console.log(
    `cross-key (${result.crossKey.mode}) median fastest=${result.crossKey.fastestMedianUs}us ` +
    `slowest=${result.crossKey.slowestMedianUs}us ` +
    `ratio=${result.crossKey.slowestToFastestRatio}x`,
  );
}

const opts = parseArgs();
const cfg = resolveConfig(opts);
const targetNames = resolveTargets(opts.target);

const startedAt = new Date();
const runId = `sign-timing-${startedAt.toISOString().replace(/[:.]/g, '-')}`;
const resultsDir = join(ROOT, 'timing-results', runId);
mkdirSync(resultsDir, { recursive: true });

console.log('╔══════════════════════════════════════════╗');
console.log('║        Signing Timing Harness           ║');
console.log('╚══════════════════════════════════════════╝');
console.log(`  targets:          ${targetNames.join(', ')}`);
console.log(`  profile:          ${opts.profile}`);
console.log(`  key count:        ${cfg.keyCount}`);
console.log(`  samples / key:    ${cfg.samplesPerKey}`);
console.log(`  warmup / key:     ${cfg.warmupPerKey}`);
console.log(`  same-key samples: ${cfg.sameKeySamples}`);
console.log(`  cross-key mode:   ${cfg.crossKeyMode}`);
console.log(`  skip same-key:    ${cfg.skipSameKey}`);
console.log(`  message length:   ${cfg.messageLength}`);
console.log(`  results dir:      ${resultsDir}`);

const summary = {
  runId,
  startedAt: startedAt.toISOString(),
  finishedAt: null,
  nodeVersion: process.version,
  platform: process.platform,
  arch: process.arch,
  config: {
    target: opts.target,
    profile: opts.profile,
    ...cfg,
  },
  clockProbe: clockProbe(),
  targets: {},
};

for (const name of targetNames) {
  console.log(`\n[measure] ${name}`);
  const { mod } = await loadTarget(name);
  const sameKey = cfg.skipSameKey ? null : measureSameKeyScenarios(mod, cfg, name);
  const crossKey = measureCrossKeyDeterministic(mod, cfg, name);
  const result = { crossKey, ...(sameKey ? { sameKey } : {}) };
  summary.targets[name] = result;
  printTargetSummary(name, result);
}

summary.finishedAt = new Date().toISOString();

const summaryPath = join(resultsDir, 'summary.json');
writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);

console.log(`\nsummary written to ${summaryPath}`);
