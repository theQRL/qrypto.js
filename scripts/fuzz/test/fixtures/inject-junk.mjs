#!/usr/bin/env node
// Fault-injection fixture: a harness that records one JUNK_RETURN finding
// (cryptoSignOpen returning a truthy non-Uint8Array). Proves the
// open-never-returns-junk class maps to exit 2.
import { Verdict } from '../../engine/verdict.mjs';

const verdict = new Verdict();
process.stderr.write('[inject-junk] injecting one JUNK_RETURN finding\n');
verdict.record('JUNK_RETURN');
process.exit(verdict.exitCode());
