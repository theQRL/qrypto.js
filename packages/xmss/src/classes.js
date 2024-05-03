/// <reference path="typedefs.js" />

class TreeHashInstClass {
  constructor(n = 0) {
    this.h = 0;
    this.nextIdx = 0;
    this.stackUsage = 0;
    this.completed = 0;
    this.node = new Uint8Array(n);
  }
}

/**
 * @param {Uint32Array[number]} n
 * @returns {TreeHashInst}
 */
export function newTreeHashInst(n) {
  return new TreeHashInstClass(n);
}

class BDSStateClass {
  constructor(height, n, k) {
    this.stackOffset = 0;
    this.stack = new Uint8Array((height + 1) * n);
    this.stackLevels = new Uint8Array(height + 1);
    this.auth = new Uint8Array(height * n);
    this.keep = new Uint8Array((height >> 1) * n);
    this.treeHash = new Array(0);
    for (let i = 0; i < height - k; i++) {
      this.treeHash.push(newTreeHashInst(n));
    }
    this.retain = new Uint8Array(((1 << k) - k - 1) * n);
    this.nextLeaf = 0;
  }
}

/**
 * @param {Uint32Array[number]} height
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} k
 * @returns {BDSState}
 */
export function newBDSState(height, n, k) {
  return new BDSStateClass(height, n, k);
}
