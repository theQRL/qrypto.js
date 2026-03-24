#!/usr/bin/env node

import { fork } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync, createWriteStream } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');

const HARNESSES = [
  { name: 'verify-src',  script: 'packages/mldsa87/fuzz/verify-src.mjs' },
  { name: 'open-src',    script: 'packages/mldsa87/fuzz/open-src.mjs' },
  { name: 'unpack-sig',  script: 'packages/mldsa87/fuzz/unpack-sig.mjs' },
  { name: 'verify-dist', script: 'packages/mldsa87/fuzz/verify-dist.mjs' },
];

const PROFILES = {
  quick:   10_000,
  nightly: 100_000,
  deep:    1_000_000,
};

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    seed: Date.now(),
    iterations: null,
    timeoutMs: null,
    profile: null,
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--seed' && i + 1 < args.length) opts.seed = Number(args[++i]);
    else if (args[i] === '--iterations' && i + 1 < args.length) opts.iterations = Number(args[++i]);
    else if (args[i] === '--timeout-ms' && i + 1 < args.length) opts.timeoutMs = Number(args[++i]);
    else if (args[i] === '--profile' && i + 1 < args.length) opts.profile = args[++i];
  }
  return opts;
}

function resolveIterations(opts) {
  if (opts.iterations != null) return opts.iterations;
  if (opts.profile && PROFILES[opts.profile] != null) return PROFILES[opts.profile];
  return 100_000;
}

function formatDuration(ms) {
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}m${String(s).padStart(2, '0')}s`;
}

function statusLabel(code) {
  if (code >= 2) return 'CRITICAL';
  if (code === 1) return 'INTERESTING';
  return 'CLEAN';
}

const opts = parseArgs();
const iterations = resolveIterations(opts);

const campaignTs = new Date().toISOString().replace(/[:.]/g, '-');
const LOGS_DIR = join(ROOT, 'fuzz-results', `campaign-${campaignTs}`);
mkdirSync(LOGS_DIR, { recursive: true });

console.log('╔══════════════════════════════════════════╗');
console.log('║       Fuzz Campaign Runner               ║');
console.log('╚══════════════════════════════════════════╝');
console.log(`  master seed:  ${opts.seed}`);
console.log(`  iterations:   ${iterations}${opts.profile ? ` (profile: ${opts.profile})` : ''}`);
console.log(`  timeout-ms:   ${opts.timeoutMs ?? 'default'}`);
console.log(`  harnesses:    ${HARNESSES.length}`);
console.log(`  logs dir:     ${LOGS_DIR}`);
console.log();

const results = [];

const children = HARNESSES.map((harness, idx) => {
  const scriptPath = join(ROOT, harness.script);
  const childSeed = opts.seed + idx;

  const childArgs = ['--seed', String(childSeed), '--iterations', String(iterations)];
  if (opts.timeoutMs != null) childArgs.push('--timeout-ms', String(opts.timeoutMs));

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
    stderrTail: '',
    stdoutTail: '',
  };
  results.push(entry);

  let stderrBuf = '';
  let stdoutBuf = '';

  child.stdout.on('data', (chunk) => {
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
    child.on('exit', (code) => {
      entry.endMs = Date.now();
      entry.exitCode = code ?? -1;
      entry.stderrTail = stderrBuf.slice(-2048);
      entry.stdoutTail = stdoutBuf.slice(-2048);
      const dur = formatDuration(entry.endMs - entry.startMs);
      const status = statusLabel(entry.exitCode);
      logStream.write(`\n# exit_code=${entry.exitCode}  status=${status}  duration=${dur}\n`);
      logStream.end();
      console.log(`[done] ${harness.name} exit=${entry.exitCode} status=${status} duration=${dur}`);
      resolve();
    });

    child.on('error', (err) => {
      entry.endMs = Date.now();
      entry.exitCode = entry.exitCode ?? -1;
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
const statusW = 12;
const exitW = 6;
const durW = 10;

console.log(
  'Harness'.padEnd(nameW) +
  'Status'.padEnd(statusW) +
  'Exit'.padEnd(exitW) +
  'Duration'.padEnd(durW),
);
console.log('-'.repeat(nameW + statusW + exitW + durW));

for (const r of results) {
  const dur = r.endMs ? formatDuration(r.endMs - r.startMs) : 'n/a';
  const status = statusLabel(r.exitCode);
  console.log(
    r.name.padEnd(nameW) +
    status.padEnd(statusW) +
    String(r.exitCode).padEnd(exitW) +
    dur.padEnd(durW),
  );
}

console.log();

const maxExit = Math.max(0, ...results.map((r) => r.exitCode ?? 0));
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
  logsDir: LOGS_DIR,
  maxExitCode: maxExit,
  verdict: maxExit >= 2 ? 'CRITICAL' : maxExit === 1 ? 'INTERESTING' : 'CLEAN',
  harnesses: results.map((r) => ({
    name: r.name,
    seed: r.seed,
    pid: r.pid,
    exitCode: r.exitCode,
    status: statusLabel(r.exitCode),
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
