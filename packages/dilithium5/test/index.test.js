import { expect } from 'chai';
import * as dilithium from '../src/index.js';

describe('index coverage', () => {
  it('should export all expected functions', () => {
    expect(dilithium.cryptoSignKeypair).to.be.a('function');
    expect(dilithium.cryptoSign).to.be.a('function');
    expect(dilithium.cryptoSignVerify).to.be.a('function');
  });
});
