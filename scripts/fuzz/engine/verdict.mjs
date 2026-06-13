/**
 * Shared severity contract for all fuzz harnesses.
 *
 * Exit codes: 0 = clean, 1 = interesting findings, >= 2 = critical findings.
 * The campaign runner reserves codes OUTSIDE this namespace for its own
 * conditions (78/EX_CONFIG = corpus-size refusal, 64/EX_USAGE = bad flags)
 * so "refused to start" can never be confused with "found a forgery".
 *
 * Every counted finding class MUST appear in CLASS_SEVERITY and reach the
 * process exit through a Verdict instance. A class that is counted, logged,
 * or saved to disk but cannot turn the campaign red is fail-open —
 * detection without verdict is telemetry. That is the regression this
 * module exists to prevent: harnesses must not implement bespoke exit
 * logic, and `record()` throws on classes missing from the map.
 */

export const CLASS_SEVERITY = Object.freeze({
  // --- Critical (exit 2): direct violations of the security contract. ---
  // verify accepted a mutated signature / message / pk / ctx
  FALSE_ACCEPT: 2,
  // unpackSig accepted a mutated signature and verify then accepted it
  FALSE_ACCEPT_VIA_PARSER: 2,
  // open returned a message different from the one that was signed
  FORGERY: 2,
  // open accepted a modified signed-message blob (SUF-CMA malleability)
  ACCEPT_SAME_MSG: 2,
  // open returned a truthy non-Uint8Array — junk on the success path
  JUNK_RETURN: 2,
  // parser verdict changed between two identical calls
  NON_DETERMINISTIC: 2,
  // cryptoSignOpen and cryptoSignOpenWithReason disagree on the same input
  WITHREASON_DISAGREE: 2,
  // src and dist (ESM/CJS) builds disagree on the same input
  DIVERGENCE: 2,
  // a known-good corpus tuple stopped verifying mid-run
  SANITY_FAIL: 2,
  // a documented throw/return contract was not honored
  // (e.g. wrong-typed ctx must throw TypeError and did not)
  CONTRACT_VIOLATION: 2,
  // --- Interesting (exit 1): unexpected behavior worth a human look. ---
  // verify/open threw on attacker-controllable bytes (totality violation)
  THREW: 1,
  // packSig threw on values unpackSig had just accepted
  REPACK_THROW: 1,
  // an iteration exceeded the per-iteration time budget
  TIMEOUT: 1,
  // unpackSig accepted but repacking produced different bytes
  CANON_DRIFT: 1,
});

export class Verdict {
  constructor() {
    this.counts = new Map();
  }

  /**
   * Record one or more occurrences of a finding class.
   * Throws on classes missing from CLASS_SEVERITY — a harness inventing a
   * class without declaring its severity is exactly the fail-open wiring
   * this module exists to prevent.
   *
   * @param {string} cls - A CLASS_SEVERITY key
   * @param {number} [n=1]
   */
  record(cls, n = 1) {
    if (!(cls in CLASS_SEVERITY)) {
      throw new Error(`unknown finding class "${cls}" — add it to CLASS_SEVERITY with an explicit severity`);
    }
    this.counts.set(cls, (this.counts.get(cls) ?? 0) + n);
  }

  /** @param {string} cls @returns {number} occurrences recorded */
  count(cls) {
    return this.counts.get(cls) ?? 0;
  }

  /** @returns {number} highest severity across recorded classes; 0 when clean */
  exitCode() {
    let code = 0;
    for (const [cls, n] of this.counts.entries()) {
      if (n > 0) code = Math.max(code, CLASS_SEVERITY[cls]);
    }
    return code;
  }

  /** @returns {string[]} per-class lines for the end-of-run summary */
  summaryLines() {
    const lines = [];
    for (const [cls, n] of this.counts.entries()) {
      if (n > 0) lines.push(`${cls}: count=${n} severity=${CLASS_SEVERITY[cls]}`);
    }
    if (lines.length === 0) lines.push('(no findings)');
    return lines;
  }
}
