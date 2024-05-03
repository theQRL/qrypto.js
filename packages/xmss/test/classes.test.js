import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newTreeHashInst } from '../src/classes.js';

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
});
