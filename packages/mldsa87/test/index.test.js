import { expect } from 'chai';
import * as mldsa from '../src/index.js';

describe('index coverage', () => {
  it('should export all expected functions', () => {
    expect(mldsa.cryptoSignKeypair).to.be.a('function');
    expect(mldsa.cryptoSign).to.be.a('function');
    expect(mldsa.cryptoSignVerify).to.be.a('function');
  });
});
