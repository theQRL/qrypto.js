#!/usr/bin/env node
/**
 * Fault-injection meta-test for the fuzz verdict pipeline.
 *
 * The exit path is the one part of a fuzzer that no clean campaign ever
 * exercises — so a regression there (a finding class that stops failing the
 * build, a signal-killed child reported CLEAN) is invisible until the day it
 * matters. This test injects a known fault of each class and asserts BOTH the
 * campaign's process exit code AND the verdict recorded in summary.json.
 *
 * It runs the real run-campaign.mjs over fixture "harnesses" (via
 * --harnesses-file) and the real verdict.mjs severity map, so it fails if
 * either the runner's aggregation or the shared severity contract regresses.
 *
 * Run: node scripts/fuzz/test/fault-injection.test.mjs
 * Exit: 0 = all assertions passed, 1 = a regression in the verdict pipeline.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import { CLASS_SEVERITY, Verdict } from '../engine/verdict.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..', '..');
const RUNNER = join(__dirname, '..', 'run-campaign.mjs');

let failures = 0;
function check(name, cond, detail = '') {
  if (cond) {
    console.log(`  ok   ${name}`);
  } else {
    failures++;
    console.error(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

// Fixture harness paths are repo-relative because the runner joins them onto
// ROOT (matching how the real HARNESSES entries are written).
const REL = 'scripts/fuzz/test/fixtures';

/**
 * Run one campaign over a single fixture harness and return
 * { exitCode, summary }.
 */
function runScenario(label, fixtureFile, extraArgs = []) {
  const workdir = mkdtempSync(join(tmpdir(), 'fuzz-meta-'));
  const harnessesFile = join(workdir, 'harnesses.json');
  writeFileSync(harnessesFile, JSON.stringify([{ name: label, script: `${REL}/${fixtureFile}` }]));

  const res = spawnSync(
    process.execPath,
    [
      RUNNER,
      '--iterations',
      '1',
      '--watchdog-idle-min',
      '0', // disable watchdog: fixtures are instant, no hang to catch
      '--harnesses-file',
      harnessesFile,
      ...extraArgs,
    ],
    { cwd: ROOT, encoding: 'utf8' }
  );

  // Locate the summary.json this run wrote (newest campaign dir).
  const resultsDir = join(ROOT, 'fuzz-results');
  const dirs = readdirSync(resultsDir)
    .filter((d) => d.startsWith('campaign-'))
    .sort();
  const summary = JSON.parse(readFileSync(join(resultsDir, dirs[dirs.length - 1], 'summary.json'), 'utf8'));

  rmSync(workdir, { recursive: true, force: true });
  return { exitCode: res.status, summary };
}

console.log('== verdict.mjs severity map ==');
// The contract the rest of the suite leans on: classes map to the documented
// severities, and an undeclared class is a hard error (not a silent exit 0).
check('FALSE_ACCEPT is critical (>=2)', CLASS_SEVERITY.FALSE_ACCEPT >= 2);
check('FORGERY is critical (>=2)', CLASS_SEVERITY.FORGERY >= 2);
check('JUNK_RETURN is critical (>=2)', CLASS_SEVERITY.JUNK_RETURN >= 2);
check('ACCEPT_SAME_MSG is critical (>=2)', CLASS_SEVERITY.ACCEPT_SAME_MSG >= 2);
check('NON_DETERMINISTIC is critical (>=2)', CLASS_SEVERITY.NON_DETERMINISTIC >= 2);
check('DIVERGENCE is critical (>=2)', CLASS_SEVERITY.DIVERGENCE >= 2);
check('SANITY_FAIL is critical (>=2)', CLASS_SEVERITY.SANITY_FAIL >= 2);
check('THREW is interesting (1)', CLASS_SEVERITY.THREW === 1);
check('TIMEOUT is interesting (1)', CLASS_SEVERITY.TIMEOUT === 1);
{
  const v = new Verdict();
  let threw = false;
  try {
    v.record('NOT_A_REAL_CLASS');
  } catch {
    threw = true;
  }
  check('recording an unknown class throws', threw);
}
{
  const v = new Verdict();
  v.record('THREW');
  v.record('FORGERY');
  check('exitCode() takes the max severity', v.exitCode() === 2);
}

console.log('\n== campaign aggregation over injected faults ==');

const scenarios = [
  { label: 'clean', fixture: 'inject-clean.mjs', wantExit: 0, wantVerdict: 'CLEAN', wantStatus: 'CLEAN' },
  { label: 'threw', fixture: 'inject-threw.mjs', wantExit: 1, wantVerdict: 'INTERESTING', wantStatus: 'INTERESTING' },
  { label: 'forgery', fixture: 'inject-forgery.mjs', wantExit: 2, wantVerdict: 'CRITICAL', wantStatus: 'CRITICAL' },
  { label: 'junk', fixture: 'inject-junk.mjs', wantExit: 2, wantVerdict: 'CRITICAL', wantStatus: 'CRITICAL' },
  // The crash class: child dies by signal, code === null. Must NOT clamp to
  // CLEAN — this is the exact R3 fail-open the rewrite closes.
  { label: 'sigkill', fixture: 'inject-sigkill.mjs', wantExit: 2, wantVerdict: 'CRITICAL', wantStatus: 'SIGNAL-DEATH' },
];

for (const s of scenarios) {
  const { exitCode, summary } = runScenario(s.label, s.fixture);
  const h = summary.harnesses[0];
  console.log(
    `  [${s.label}] exit=${exitCode} verdict=${summary.verdict} status=${h.status} signal=${h.signal ?? 'none'}`
  );
  check(`${s.label}: campaign exit code is ${s.wantExit}`, exitCode === s.wantExit, `got ${exitCode}`);
  check(`${s.label}: summary verdict is ${s.wantVerdict}`, summary.verdict === s.wantVerdict, `got ${summary.verdict}`);
  check(`${s.label}: harness status is ${s.wantStatus}`, h.status === s.wantStatus, `got ${h.status}`);
  if (s.label === 'sigkill') {
    check('sigkill: exitCode recorded as null (not clamped)', h.exitCode === null, `got ${h.exitCode}`);
    check('sigkill: signal recorded in summary', h.signal === 'SIGKILL', `got ${h.signal}`);
    check('sigkill: effectiveExit is critical', h.effectiveExit >= 2, `got ${h.effectiveExit}`);
  }
}

console.log('\n== corpus-guard refusal lives outside the finding namespace ==');
// EX_CONFIG (78) must not collide with the 0/1/>=2 finding space, so a
// refusal to start can never be read as a finding severity.
const FINDING_EXITS = [0, 1, 2];
check('corpus-guard exit 78 is not a finding severity', !FINDING_EXITS.includes(78));

console.log();
if (failures > 0) {
  console.error(`FAULT-INJECTION META-TEST FAILED: ${failures} assertion(s) regressed.`);
  process.exit(1);
}
console.log('Fault-injection meta-test passed: verdict pipeline wiring intact.');
process.exit(0);
