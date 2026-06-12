/**
 * Save-budget policy for fuzz harnesses.
 *
 * Persisting every interesting-looking case floods the corpus directory:
 * a single deep campaign once wrote 400k+ files (15 GB) of *expected*
 * validation throws. The budget keeps full counters for everything but
 * caps what actually hits disk:
 *
 *   - per (label, errorClass): at most `perClassCap` saved cases per run —
 *     a few dozen exemplars of one failure shape is plenty to debug from;
 *   - globally: at most `globalCap` saved cases per run.
 *
 * Nothing is dropped silently: `summaryLines()` reports counted vs saved vs
 * suppressed per class so the campaign log always states what was capped.
 * Expected-behavior cases (e.g. a parser rejecting wrong-length input by
 * throwing its documented validation error) should not be routed through
 * the budget at all — count them in harness stats and never save.
 */

export class SaveBudget {
  constructor({ perClassCap = 24, globalCap = 500 } = {}) {
    this.perClassCap = perClassCap;
    this.globalCap = globalCap;
    this.savedTotal = 0;
    this.classes = new Map(); // key -> { counted, saved }
  }

  /**
   * Record an occurrence of (label, errorClass) and decide whether this
   * case should be persisted. Always counts; returns true while the
   * per-class and global caps have headroom.
   *
   * @param {string} label - Harness-level case label (e.g. 'THROW', 'DIVERGENCE')
   * @param {string} [errorClass] - Normalized error class (see classifyError)
   * @returns {boolean} true if the caller should write the case to disk
   */
  shouldSave(label, errorClass = '') {
    const key = errorClass ? `${label}:${errorClass}` : label;
    let entry = this.classes.get(key);
    if (!entry) {
      entry = { counted: 0, saved: 0 };
      this.classes.set(key, entry);
    }
    entry.counted++;
    if (entry.saved >= this.perClassCap) return false;
    if (this.savedTotal >= this.globalCap) return false;
    entry.saved++;
    this.savedTotal++;
    return true;
  }

  /** Total number of cases suppressed by the caps. */
  suppressedCount() {
    let suppressed = 0;
    for (const entry of this.classes.values()) {
      suppressed += entry.counted - entry.saved;
    }
    return suppressed;
  }

  /**
   * Human-readable per-class accounting for the end-of-run summary.
   * @returns {string[]} lines like "THROW:range error (#): counted=120 saved=24 suppressed=96"
   */
  summaryLines() {
    const lines = [];
    for (const [key, entry] of this.classes.entries()) {
      const suppressed = entry.counted - entry.saved;
      lines.push(`${key}: counted=${entry.counted} saved=${entry.saved} suppressed=${suppressed}`);
    }
    if (lines.length === 0) lines.push('(no saveable cases this run)');
    return lines;
  }
}

/**
 * Normalize an error message into a stable class key so the same failure
 * shape dedupes regardless of embedded lengths/offsets/hex.
 *
 * @param {string} message
 * @returns {string}
 */
export function classifyError(message) {
  return String(message ?? 'unknown')
    .replace(/0x[0-9a-fA-F]+/g, '#')
    .replace(/\d+/g, '#')
    .slice(0, 120);
}
