#!/usr/bin/env node

import { fork } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  mkdirSync,
  writeFileSync,
  createWriteStream,
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  rmSync,
} from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');

// Exit-code contract (documented in CONTRIBUTING.md "Fuzzing"):
//   0 = clean, 1 = interesting findings, >= 2 = critical findings
//   (per-harness severities come from scripts/fuzz/engine/verdict.mjs).
// Runner-level refusals live OUTSIDE that namespace so they can never be
// confused with findings:
const EXIT_USAGE = 64; // EX_USAGE: contradictory flags
const EXIT_CORPUS_GUARD = 78; // EX_CONFIG: refused to start over a bloated corpus

const HARNESSES = [
  { name: 'verify-src', script: 'packages/mldsa87/fuzz/verify-src.mjs' },
  { name: 'open-src', script: 'packages/mldsa87/fuzz/open-src.mjs' },
  { name: 'unpack-sig', script: 'packages/mldsa87/fuzz/unpack-sig.mjs' },
  { name: 'verify-dist', script: 'packages/mldsa87/fuzz/verify-dist.mjs' },
  { name: 'd5-verify-src', script: 'packages/dilithium5/fuzz/verify-src.mjs' },
  { name: 'd5-open-src', script: 'packages/dilithium5/fuzz/open-src.mjs' },
  { name: 'd5-unpack-sig', script: 'packages/dilithium5/fuzz/unpack-sig.mjs' },
  { name: 'd5-verify-dist', script: 'packages/dilithium5/fuzz/verify-dist.mjs' },
];

const PROFILES = {
  quick: 10_000, // per-push CI gate
  weekly: 100_000, // scheduled Sunday run (fuzz-scheduled.yml)
  deep: 1_000_000, // audit-level review only — run on demand, never scheduled
};

const CORPUS_DIRS = [
  join(ROOT, 'packages', 'mldsa87', 'fuzz', 'corpus'),
  join(ROOT, 'packages', 'dilithium5', 'fuzz', 'corpus'),
];

// Refuse to start when the accumulated corpus is suspiciously large — a past
// campaign once left 400k+ files / 15 GB of expected-throw cases behind.
// Harness-side save budgets now bound per-run growth; this guard catches
// pre-existing accumulation. Override with --allow-large-corpus, or purge
// with --clean-corpus.
const CORPUS_MAX_FILES = 5_000;
const CORPUS_MAX_BYTES = 512 * 1024 * 1024;

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    seed: Date.now(),
    iterations: null,
    timeoutMs: null,
    profile: null,
    cleanCorpus: false,
    allowLargeCorpus: false,
    // Per-child inactivity watchdog, minutes (fractions allowed; 0 disables).
    // Harnesses print progress every <=2000 iterations, so a healthy child is
    // never silent for long; a synchronously hung one is silent forever —
    // which post-hoc performance.now() checks inside the child can never see.
    watchdogIdleMin: 10,
    // Test infrastructure (fault-injection meta-test): JSON file replacing
    // the harness list with fixture harnesses.
    harnessesFile: null,
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--seed' && i + 1 < args.length) opts.seed = Number(args[++i]);
    else if (args[i] === '--iterations' && i + 1 < args.length) opts.iterations = Number(args[++i]);
    else if (args[i] === '--timeout-ms' && i + 1 < args.length) opts.timeoutMs = Number(args[++i]);
    else if (args[i] === '--profile' && i + 1 < args.length) opts.profile = args[++i];
    else if (args[i] === '--watchdog-idle-min' && i + 1 < args.length) opts.watchdogIdleMin = Number(args[++i]);
    else if (args[i] === '--harnesses-file' && i + 1 < args.length) opts.harnessesFile = args[++i];
    else if (args[i] === '--clean-corpus') opts.cleanCorpus = true;
    else if (args[i] === '--allow-large-corpus') opts.allowLargeCorpus = true;
  }
  return opts;
}

function measureDir(dir) {
  let files = 0;
  let bytes = 0;
  if (!existsSync(dir)) return { files, bytes };
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else {
        files++;
        try {
          bytes += statSync(full).size;
        } catch {
          /* removed concurrently */
        }
      }
    }
  }
  return { files, bytes };
}

function guardCorpusSize(opts) {
  if (opts.cleanCorpus) {
    for (const dir of CORPUS_DIRS) {
      if (existsSync(dir)) {
        rmSync(dir, { recursive: true, force: true });
        console.log(`[corpus] cleaned ${dir}`);
      }
    }
    return;
  }
  let files = 0;
  let bytes = 0;
  for (const dir of CORPUS_DIRS) {
    const m = measureDir(dir);
    files += m.files;
    bytes += m.bytes;
  }
  if (files === 0) return;
  const mb = (bytes / (1024 * 1024)).toFixed(1);
  console.log(`[corpus] existing corpus: ${files} files, ${mb} MB`);
  if ((files > CORPUS_MAX_FILES || bytes > CORPUS_MAX_BYTES) && !opts.allowLargeCorpus) {
    console.error(
      `[corpus] corpus exceeds limits (${CORPUS_MAX_FILES} files / ${CORPUS_MAX_BYTES / (1024 * 1024)} MB).\n` +
        `[corpus] Re-run with --clean-corpus to purge it, or --allow-large-corpus to proceed anyway.`
    );
    // EX_CONFIG — deliberately outside the 0/1/>=2 finding namespace so a
    // refusal to start can never be read as "found a forgery".
    process.exit(EXIT_CORPUS_GUARD);
  }
}

function resolveIterations(opts) {
  if (opts.iterations != null) return opts.iterations;
  if (opts.profile && PROFILES[opts.profile] != null) return PROFILES[opts.profile];
  return 100_000;
}

function resolveHarnesses(opts) {
  if (!opts.harnessesFile) return HARNESSES;
  const parsed = JSON.parse(readFileSync(opts.harnessesFile, 'utf8'));
  return parsed.map((h) => ({ name: h.name, script: h.script, extraArgs: h.extraArgs ?? [] }));
}

function formatDuration(ms) {
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}m${String(s).padStart(2, '0')}s`;
}

function statusLabel(entry) {
  if (entry.watchdogKilled) return 'WATCHDOG-KILL';
  if (entry.signal) return 'SIGNAL-DEATH';
  if (entry.spawnError) return 'SPAWN-ERROR';
  if (entry.effectiveExit >= 2) return 'CRITICAL';
  if (entry.effectiveExit === 1) return 'INTERESTING';
  return 'CLEAN';
}

const opts = parseArgs();

// --profile names an iteration budget; --iterations overrides it silently and
// past campaigns recorded misleading "profile: weekly, iterations: 200"
// summaries. Refuse the ambiguity.
if (opts.profile != null && opts.iterations != null) {
  console.error('[args] --profile and --iterations are mutually exclusive; pass one.');
  process.exit(EXIT_USAGE);
}
if (opts.profile != null && PROFILES[opts.profile] == null) {
  console.error(`[args] unknown profile "${opts.profile}" (expected: ${Object.keys(PROFILES).join(' | ')})`);
  process.exit(EXIT_USAGE);
}

guardCorpusSize(opts);
const iterations = resolveIterations(opts);
const harnesses = resolveHarnesses(opts);
const WATCHDOG_IDLE_MS = opts.watchdogIdleMin > 0 ? opts.watchdogIdleMin * 60_000 : 0;

const campaignTs = new Date().toISOString().replace(/[:.]/g, '-');
const LOGS_DIR = join(ROOT, 'fuzz-results', `campaign-${campaignTs}`);
mkdirSync(LOGS_DIR, { recursive: true });

console.log('╔══════════════════════════════════════════╗');
console.log('║       Fuzz Campaign Runner               ║');
console.log('╚══════════════════════════════════════════╝');
console.log(`  master seed:  ${opts.seed}`);
console.log(`  iterations:   ${iterations}${opts.profile ? ` (profile: ${opts.profile})` : ''}`);
console.log(`  timeout-ms:   ${opts.timeoutMs ?? 'default'}`);
console.log(`  watchdog:     ${WATCHDOG_IDLE_MS > 0 ? `${opts.watchdogIdleMin} min idle` : 'disabled'}`);
console.log(`  harnesses:    ${harnesses.length}`);
console.log(`  logs dir:     ${LOGS_DIR}`);
console.log();

const results = [];

const children = harnesses.map((harness, idx) => {
  const scriptPath = join(ROOT, harness.script);
  const childSeed = opts.seed + idx;

  const childArgs = ['--seed', String(childSeed), '--iterations', String(iterations)];
  if (opts.timeoutMs != null) childArgs.push('--timeout-ms', String(opts.timeoutMs));
  if (harness.extraArgs?.length) childArgs.push(...harness.extraArgs);

  const startMs = Date.now();
  console.log(`[launch] ${harness.name} (pid pending) seed=${childSeed}`);

  const child = fork(scriptPath, childArgs, {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });

  console.log(`[launch] ${harness.name} pid=${child.pid}`);

  const logStream = createWriteStream(join(LOGS_DIR, `${harness.name}.log`));
  logStream.write(`# ${harness.name}\n`);
  logStream.write(`# seed=${childSeed}  iterations=${iterations}  started=${new Date().toISOString()}\n`);
  logStream.write(`# pid=${child.pid}\n\n`);

  const entry = {
    name: harness.name,
    pid: child.pid,
    seed: childSeed,
    startMs,
    endMs: null,
    exitCode: null,
    signal: null,
    effectiveExit: null,
    watchdogKilled: false,
    spawnError: null,
    stderrTail: '',
    stdoutTail: '',
  };
  results.push(entry);

  let stderrBuf = '';
  let stdoutBuf = '';

  // Per-child inactivity watchdog: a synchronously hung harness produces no
  // further output and no exit — the only place that can detect and break a
  // hang is here in the runner. Kill + mark critical.
  let watchdogTimer = null;
  const armWatchdog = () => {
    if (WATCHDOG_IDLE_MS <= 0) return;
    clearTimeout(watchdogTimer);
    watchdogTimer = setTimeout(() => {
      entry.watchdogKilled = true;
      const idleMin = opts.watchdogIdleMin;
      console.error(`[watchdog] ${harness.name} silent for ${idleMin} min — killing pid ${child.pid} (probable hang)`);
      logStream.write(`\n# watchdog: no output for ${idleMin} min — killed as probable hang\n`);
      child.kill('SIGKILL');
    }, WATCHDOG_IDLE_MS);
  };
  armWatchdog();

  child.stdout.on('data', (chunk) => {
    armWatchdog();
    const text = chunk.toString();
    stdoutBuf += text;
    if (stdoutBuf.length > 8192) stdoutBuf = stdoutBuf.slice(-8192);
    logStream.write(text);
    const lines = text.split('\n').filter(Boolean);
    for (const line of lines) {
      process.stdout.write(`[${harness.name}] ${line}\n`);
    }
  });

  child.stderr.on('data', (chunk) => {
    armWatchdog();
    const text = chunk.toString();
    stderrBuf += text;
    if (stderrBuf.length > 8192) stderrBuf = stderrBuf.slice(-8192);
    logStream.write(`[stderr] ${text}`);
    const lines = text.split('\n').filter(Boolean);
    for (const line of lines) {
      process.stderr.write(`[${harness.name}] ${line}\n`);
    }
  });

  const done = new Promise((resolve) => {
    child.on('exit', (code, signal) => {
      clearTimeout(watchdogTimer);
      entry.endMs = Date.now();
      entry.exitCode = code; // null when killed by a signal — keep it visible
      entry.signal = signal ?? null;
      // Signal death (OOM SIGKILL, SIGSEGV, watchdog kill) is the crash
      // class fuzzing exists to surface — it must read as critical, never
      // be clamped to CLEAN.
      entry.effectiveExit = code === null ? 2 : code;
      entry.stderrTail = stderrBuf.slice(-2048);
      entry.stdoutTail = stdoutBuf.slice(-2048);
      const dur = formatDuration(entry.endMs - entry.startMs);
      const status = statusLabel(entry);
      logStream.write(
        `\n# exit_code=${entry.exitCode}  signal=${entry.signal ?? 'none'}  status=${status}  duration=${dur}\n`
      );
      logStream.end();
      console.log(
        `[done] ${harness.name} exit=${entry.exitCode}${entry.signal ? ` signal=${entry.signal}` : ''} status=${status} duration=${dur}`
      );
      resolve();
    });

    child.on('error', (err) => {
      clearTimeout(watchdogTimer);
      entry.endMs = Date.now();
      entry.spawnError = err.message;
      // A harness that could not run verified nothing — critical, not clean.
      entry.effectiveExit = 2;
      entry.stderrTail = err.message;
      logStream.write(`\n# error: ${err.message}\n`);
      logStream.end();
      console.error(`[error] ${harness.name}: ${err.message}`);
      resolve();
    });
  });

  return done;
});

await Promise.all(children);

console.log();
console.log('═══════════════════════════════════════════════════════════════');
console.log('  CAMPAIGN RESULTS');
console.log('═══════════════════════════════════════════════════════════════');
console.log();

const nameW = 16;
const statusW = 15;
const exitW = 12;
const durW = 10;

console.log('Harness'.padEnd(nameW) + 'Status'.padEnd(statusW) + 'Exit'.padEnd(exitW) + 'Duration'.padEnd(durW));
console.log('-'.repeat(nameW + statusW + exitW + durW));

for (const r of results) {
  const dur = r.endMs ? formatDuration(r.endMs - r.startMs) : 'n/a';
  const exitText = r.signal ? `${r.exitCode}/${r.signal}` : String(r.exitCode);
  console.log(r.name.padEnd(nameW) + statusLabel(r).padEnd(statusW) + exitText.padEnd(exitW) + dur.padEnd(durW));
}

console.log();

const maxExit = Math.max(0, ...results.map((r) => r.effectiveExit ?? 2));
if (maxExit >= 2) {
  console.log('*** CRITICAL findings detected ***');
} else if (maxExit === 1) {
  console.log('*** INTERESTING findings detected ***');
} else {
  console.log('All harnesses clean.');
}

const summary = {
  campaign: campaignTs,
  masterSeed: opts.seed,
  profile: opts.profile ?? null,
  requestedIterations: iterations,
  timeoutMs: opts.timeoutMs ?? null,
  watchdogIdleMin: opts.watchdogIdleMin,
  logsDir: LOGS_DIR,
  maxExitCode: maxExit,
  verdict: maxExit >= 2 ? 'CRITICAL' : maxExit === 1 ? 'INTERESTING' : 'CLEAN',
  harnesses: results.map((r) => ({
    name: r.name,
    seed: r.seed,
    pid: r.pid,
    exitCode: r.exitCode,
    signal: r.signal,
    effectiveExit: r.effectiveExit,
    watchdogKilled: r.watchdogKilled,
    spawnError: r.spawnError,
    status: statusLabel(r),
    durationMs: r.endMs ? r.endMs - r.startMs : null,
    durationHuman: r.endMs ? formatDuration(r.endMs - r.startMs) : 'n/a',
    stderrTail: r.stderrTail,
    stdoutTail: r.stdoutTail,
  })),
};

writeFileSync(join(LOGS_DIR, 'summary.json'), JSON.stringify(summary, null, 2));
console.log(`\nSummary written to: ${join(LOGS_DIR, 'summary.json')}`);
console.log(`Logs directory:     ${LOGS_DIR}`);

process.exit(maxExit);
