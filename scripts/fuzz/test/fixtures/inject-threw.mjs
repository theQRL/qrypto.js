#!/usr/bin/env node
// Fault-injection fixture: a harness that records one THREW finding.
// Used by fault-injection.test.mjs to prove THREW maps to exit 1 through the
// shared verdict map and the campaign runner aggregates it as INTERESTING.
import { Verdict } from '../../engine/verdict.mjs';

const verdict = new Verdict();
process.stderr.write('[inject-threw] injecting one THREW finding\n');
verdict.record('THREW');
process.exit(verdict.exitCode());
