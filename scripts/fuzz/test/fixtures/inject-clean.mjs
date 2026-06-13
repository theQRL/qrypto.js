#!/usr/bin/env node
// Fault-injection fixture: a clean harness (no findings, exit 0). Provides
// the negative control so the meta-test confirms a clean campaign stays
// CLEAN rather than only ever asserting failures.
import { Verdict } from '../../engine/verdict.mjs';

const verdict = new Verdict();
process.stderr.write('[inject-clean] no findings\n');
process.exit(verdict.exitCode());
