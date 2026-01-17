function getMochaGlobal(name) {
  const value = globalThis && globalThis[name];
  if (typeof value !== 'function') {
    throw new Error(`Mocha global "${name}" is not available`);
  }
  return value;
}

export const describe = (...args) => getMochaGlobal('describe')(...args);
export const it = (...args) => getMochaGlobal('it')(...args);
export const before = (...args) => getMochaGlobal('before')(...args);
export const after = (...args) => getMochaGlobal('after')(...args);
export const beforeEach = (...args) => getMochaGlobal('beforeEach')(...args);
export const afterEach = (...args) => getMochaGlobal('afterEach')(...args);
