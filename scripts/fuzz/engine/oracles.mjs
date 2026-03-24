export class OracleViolation extends Error {
  constructor(message, label, detail) {
    super(`[${label}] ${message}`);
    this.name = 'OracleViolation';
    this.label = label;
    this.detail = detail;
  }
}

export function checkNoFalseAccept(result, label = 'noFalseAccept') {
  if (result === true || (result && typeof result !== 'object')) {
    throw new OracleViolation(
      `Mutated input was accepted (result: ${String(result)})`,
      label,
      { result },
    );
  }
}

export function checkOpenNeverReturnsJunk(result, label = 'openNeverReturnsJunk') {
  if (result !== undefined && result !== null && result !== false) {
    throw new OracleViolation(
      `Invalid input produced non-empty result: ${typeof result}`,
      label,
      { resultType: typeof result, preview: String(result).slice(0, 120) },
    );
  }
}

export function checkDeterministic(fn, args, iterations = 5, label = 'deterministic') {
  const results = [];
  for (let i = 0; i < iterations; i++) {
    results.push(fn(...args));
  }

  const baseline = serialize(results[0]);
  for (let i = 1; i < results.length; i++) {
    const current = serialize(results[i]);
    if (current !== baseline) {
      throw new OracleViolation(
        `Non-deterministic result on iteration ${i + 1}`,
        label,
        { iteration: i + 1, baseline: baseline.slice(0, 200), divergent: current.slice(0, 200) },
      );
    }
  }
}

export async function checkNoHang(fn, args, timeoutMs = 5000, label = 'noHang') {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new OracleViolation(
        `Function exceeded ${timeoutMs}ms timeout`,
        label,
        { timeoutMs },
      ));
    }, timeoutMs);

    try {
      const result = fn(...args);
      if (result && typeof result.then === 'function') {
        result.then(
          (v) => { clearTimeout(timer); resolve(v); },
          (e) => { clearTimeout(timer); reject(e); },
        );
      } else {
        clearTimeout(timer);
        resolve(result);
      }
    } catch (err) {
      clearTimeout(timer);
      reject(err);
    }
  });
}

export function checkSrcDistAgree(srcResult, distResult, label = 'srcDistAgree') {
  const a = serialize(srcResult);
  const b = serialize(distResult);
  if (a !== b) {
    throw new OracleViolation(
      'Source and dist results disagree',
      label,
      { src: a.slice(0, 200), dist: b.slice(0, 200) },
    );
  }
}

function serialize(value) {
  if (value instanceof Uint8Array) {
    return Array.from(value).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  if (typeof value === 'boolean') return String(value);
  if (value === undefined) return 'undefined';
  if (value === null) return 'null';
  if (typeof value === 'object') return JSON.stringify(value, replacer);
  return String(value);
}

function replacer(_key, value) {
  if (value instanceof Uint8Array || (value && value.constructor && value.constructor.name === 'Uint8Array')) {
    return { __uint8: Array.from(value) };
  }
  return value;
}
