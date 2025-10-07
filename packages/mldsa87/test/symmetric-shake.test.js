import { expect } from 'chai';
import { mldsaShake128StreamInit, mldsaShake256StreamInit } from '../src/symmetric-shake.js';

describe('symmetric-shake', () => {
  it('invalid key length in mldsaShake128StreamInit throws', () => {
    expect(() => {
      mldsaShake128StreamInit(1, 2, 3, 4);
    }).to.throw();
  });
  it('invalid key length in mldsaShake256StreamInit throws', () => {
    expect(() => {
      mldsaShake256StreamInit(1, 2, 3, 4);
    }).to.throw();
  });
});
