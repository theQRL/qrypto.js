import { expect } from 'chai';

describe('helper', () => {
  it('invalid key length in polyVecLUniformEta throws', () => {
    expect(() => {
      polyVecLUniformEta(1, 2, 3);
    }).to.throw();
  });
});
