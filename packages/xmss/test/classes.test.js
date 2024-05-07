import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newTreeHashInst, newWOTSParams, newXMSSParams } from '../src/classes.js';

describe('classes', () => {
  describe('newTreeHashInst', () => {
    it('should create a TreeHashInst instance', () => {
      const treeHashInst = newTreeHashInst(8);

      expect(Object.getOwnPropertyNames(treeHashInst)).to.deep.equal([
        'h',
        'nextIdx',
        'stackUsage',
        'completed',
        'node',
      ]);
      expect(treeHashInst.completed).to.equal(0);
      expect(treeHashInst.h).to.equal(0);
      expect(treeHashInst.nextIdx).to.equal(0);
      expect(treeHashInst.node).to.deep.equal(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]));
      expect(treeHashInst.node.length).to.equal(8);
      expect(treeHashInst.stackUsage).to.equal(0);
    });

    it('should create a TreeHashInst instance with default n value 0', () => {
      const treeHashInst = newTreeHashInst();

      expect(treeHashInst.node).to.deep.equal(new Uint8Array([]));
      expect(treeHashInst.node.length).to.equal(0);
    });
  });

  describe('newBDSState', () => {
    it('should create a BDSState instance', () => {
      const height = 10;
      const n = 6;
      const k = 9;
      const bdsState = newBDSState(height, n, k);

      expect(Object.getOwnPropertyNames(bdsState)).to.deep.equal([
        'stackOffset',
        'stack',
        'stackLevels',
        'auth',
        'keep',
        'treeHash',
        'retain',
        'nextLeaf',
      ]);
      expect(bdsState.stackOffset).to.equal(0);
      expect(bdsState.stack.length).to.equal((height + 1) * n);
      expect(bdsState.stackLevels.length).to.equal(height + 1);
      expect(bdsState.auth.length).to.equal(height * n);
      expect(bdsState.keep.length).to.equal((height >> 1) * n);
      expect(bdsState.treeHash.length).to.equal(height - k);
      expect(bdsState.retain.length).to.equal(((1 << k) - k - 1) * n);
      expect(bdsState.nextLeaf).to.equal(0);
    });
  });

  describe('newWOTSParams', () => {
    it('should create a WOTSParams instance, with n[6] and w[9]', () => {
      const n = 6;
      const w = 9;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(16);
      expect(wotsParams.len2).to.equal(3);
      expect(wotsParams.len).to.equal(19);
      expect(wotsParams.n).to.equal(6);
      expect(wotsParams.w).to.equal(9);
      expect(wotsParams.logW).to.equal(3);
      expect(wotsParams.keySize).to.equal(114);
    });

    it('should create a WOTSParams instance, with n[32] and w[16]', () => {
      const n = 32;
      const w = 16;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(64);
      expect(wotsParams.len2).to.equal(3);
      expect(wotsParams.len).to.equal(67);
      expect(wotsParams.n).to.equal(32);
      expect(wotsParams.w).to.equal(16);
      expect(wotsParams.logW).to.equal(4);
      expect(wotsParams.keySize).to.equal(2144);
    });

    it('should create a WOTSParams instance, with n[8] and w[7]', () => {
      const n = 8;
      const w = 7;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(32);
      expect(wotsParams.len2).to.equal(4);
      expect(wotsParams.len).to.equal(36);
      expect(wotsParams.n).to.equal(8);
      expect(wotsParams.w).to.equal(7);
      expect(wotsParams.logW).to.equal(2);
      expect(wotsParams.keySize).to.equal(288);
    });

    it('should create a WOTSParams instance, with n[13] and w[11]', () => {
      const n = 13;
      const w = 11;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(34);
      expect(wotsParams.len2).to.equal(3);
      expect(wotsParams.len).to.equal(37);
      expect(wotsParams.n).to.equal(13);
      expect(wotsParams.w).to.equal(11);
      expect(wotsParams.logW).to.equal(3);
      expect(wotsParams.keySize).to.equal(481);
    });

    it('should create a WOTSParams instance, with n[7] and w[8]', () => {
      const n = 7;
      const w = 8;
      const wotsParams = newWOTSParams(n, w);

      expect(Object.getOwnPropertyNames(wotsParams)).to.deep.equal([
        'n',
        'w',
        'logW',
        'len1',
        'len2',
        'len',
        'keySize',
      ]);
      expect(wotsParams.n).to.equal(n);
      expect(wotsParams.w).to.equal(w);
      expect(wotsParams.len1).to.equal(18);
      expect(wotsParams.len2).to.equal(3);
      expect(wotsParams.len).to.equal(21);
      expect(wotsParams.n).to.equal(7);
      expect(wotsParams.w).to.equal(8);
      expect(wotsParams.logW).to.equal(3);
      expect(wotsParams.keySize).to.equal(147);
    });
  });

  describe('newXMSSParams', () => {
    it('should create a WOTSParams instance', () => {
      const n = 2;
      const h = 4;
      const w = 6;
      const k = 8;
      const xmssParams = newXMSSParams(n, h, w, k);

      expect(Object.getOwnPropertyNames(xmssParams)).to.deep.equal(['wotsParams', 'n', 'h', 'k']);
      expect(xmssParams.wotsParams).to.deep.equal(newWOTSParams(n, w));
      expect(xmssParams.n).to.equal(n);
      expect(xmssParams.h).to.equal(h);
      expect(xmssParams.k).to.equal(k);
    });
  });
});
