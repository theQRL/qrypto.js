import { expect } from 'chai';
import { dilithiumShake128StreamInit, dilithiumShake256StreamInit } from '../src/symmetric-shake.js';

describe('symmetric-shake', () => {
  it('invalid key length in dilithiumShake128StreamInit throws', () => {
    expect(() => {
      dilithiumShake128StreamInit(1, 2, 3, 4);
    }).to.throw();
  });
  it('invalid key length in dilithiumShake256StreamInit throws', () => {
    expect(() => {
      dilithiumShake256StreamInit(1, 2, 3, 4);
    }).to.throw();
  });
});
