function isTypedArray(value) {
  return ArrayBuffer.isView(value) && !(value instanceof DataView);
}

function isObject(value) {
  return value !== null && typeof value === 'object';
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (isTypedArray(a) && isTypedArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (isObject(a) && isObject(b)) {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    for (const key of keysA) {
      if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
      if (!deepEqual(a[key], b[key])) return false;
    }
    return true;
  }
  return false;
}

class Assertion {
  constructor(actual, negate, deep, message) {
    this.actual = actual;
    this.negate = negate;
    this._deep = deep;
    this.message = message || '';
  }

  get to() {
    return this;
  }

  get be() {
    return this;
  }

  get not() {
    return new Assertion(this.actual, !this.negate, this.deep, this.message);
  }

  get deep() {
    return new Assertion(this.actual, this.negate, true, this.message);
  }

  _assert(condition, defaultMessage, negatedMessage) {
    const ok = this.negate ? !condition : condition;
    if (!ok) {
      const message = this.message || (this.negate ? negatedMessage : defaultMessage);
      throw new Error(message || 'Assertion failed');
    }
  }

  equal(expected, message) {
    const condition = this._deep ? deepEqual(this.actual, expected) : this.actual === expected;
    this._assert(
      condition,
      message || `expected ${String(this.actual)} to equal ${String(expected)}`,
      message || `expected ${String(this.actual)} to not equal ${String(expected)}`,
    );
    return this;
  }

  instanceOf(expected, message) {
    const condition = this.actual instanceof expected;
    this._assert(
      condition,
      message || `expected value to be instance of ${expected && expected.name ? expected.name : 'provided type'}`,
      message || `expected value to not be instance of ${expected && expected.name ? expected.name : 'provided type'}`,
    );
    return this;
  }

  an(expectedType, message) {
    let condition = false;
    if (expectedType === 'array') {
      condition = Array.isArray(this.actual);
    } else if (expectedType === 'error') {
      condition = this.actual instanceof Error;
    } else {
      condition = typeof this.actual === expectedType;
    }
    this._assert(
      condition,
      message || `expected value to be an ${expectedType}`,
      message || `expected value to not be an ${expectedType}`,
    );
    return this;
  }

  a(expectedType, message) {
    return this.an(expectedType, message);
  }

  throw(expected, message) {
    if (typeof this.actual !== 'function') {
      this._assert(false, 'expected a function to throw', 'expected a function to not throw');
      return this;
    }

    let thrown;
    try {
      this.actual();
    } catch (err) {
      thrown = err;
    }

    let condition = Boolean(thrown);
    if (condition && expected) {
      if (typeof expected === 'string') {
        const errMessage = thrown && thrown.message ? thrown.message : String(thrown);
        condition = errMessage.includes(expected);
      } else if (typeof expected === 'function') {
        condition = thrown instanceof expected;
      }
    }

    this._assert(
      condition,
      message || 'expected function to throw',
      message || 'expected function to not throw',
    );
    return this;
  }
}

export function expect(actual, message) {
  return new Assertion(actual, false, false, message);
}
