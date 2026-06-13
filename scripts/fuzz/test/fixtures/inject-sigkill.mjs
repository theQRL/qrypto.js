#!/usr/bin/env node
// Fault-injection fixture: a harness that dies by signal (the OOM-SIGKILL /
// SIGSEGV crash class). Node delivers code === null to the runner's 'exit'
// handler; the runner must treat that as critical, never clamp it to CLEAN.
process.stderr.write('[inject-sigkill] about to SIGKILL self\n');
// Flush stderr, then kill on the next tick so the line reaches the runner.
setImmediate(() => {
  process.kill(process.pid, 'SIGKILL');
});
