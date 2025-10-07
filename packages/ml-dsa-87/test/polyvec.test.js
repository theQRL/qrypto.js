import { expect } from 'chai';
import { polyVecLUniformEta, polyVecLUniformGamma1 } from '../src/polyvec.js';

describe('symmetric-shake', () => {
  it('invalid key length in polyVecLUniformEta throws', () => {
    expect(() => {
      polyVecLUniformEta(1, 2, 3);
    }).to.throw();
  });
  it('invalid key length in polyVecLUniformGamma1 throws', () => {
    expect(() => {
      polyVecLUniformGamma1(1, 2, 3);
    }).to.throw();
  });
});
