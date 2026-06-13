#!/usr/bin/env node
// Fault-injection fixture: a harness that records one FORGERY finding.
// Proves a critical class maps to exit 2 through the shared verdict map and
// the campaign runner aggregates it as CRITICAL.
import { Verdict } from '../../engine/verdict.mjs';

const verdict = new Verdict();
process.stderr.write('[inject-forgery] injecting one FORGERY finding\n');
verdict.record('FORGERY');
process.exit(verdict.exitCode());
