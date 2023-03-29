const { expect } = require('chai');
const { makeHint } = require('../src/rounding.js');

describe('rounding', () => {
  it('makeHint', () => {
    expect(makeHint(261889, 0)).to.equal(1);
    expect(makeHint(-261889, 0)).to.equal(1);
    expect(makeHint(-261888, 1)).to.equal(1);
    expect(makeHint(-261888, 0)).to.equal(0);
  });
});
