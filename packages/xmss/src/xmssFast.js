/// <reference path="typedefs.js" />
import { coreHash, hashH, prf } from './hash.js';
import {
  addrToByte,
  setChainAddr,
  setHashAddr,
  setKeyAndMask,
  setLTreeAddr,
  setOTSAddr,
  setTreeHeight,
  setTreeIndex,
  setType,
  shake256,
  toByteLittleEndian,
} from './helper.js';

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 */
export function getSeed(hashFunction, seed, skSeed, n, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const bytes = new Uint8Array(32);

  setChainAddr(addr, 0);
  setHashAddr(addr, 0);
  setKeyAndMask(addr, 0);

  addrToByte(bytes, addr);
  prf(hashFunction, seed, bytes, skSeed, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} outSeeds
 * @param {Uint8Array} inSeeds
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} len
 */
export function expandSeed(hashFunction, outSeeds, inSeeds, n, len) {
  const ctr = new Uint8Array(32);
  for (let i = 0; i < len; i++) {
    toByteLittleEndian(ctr, i, 32);
    prf(hashFunction, outSeeds.subarray(i * n, i * n + n), ctr, inSeeds, n);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
export function hashF(hashFunction, out, input, pubSeed, addr, n) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buf = new Uint8Array(n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n);

  for (let i = 0; i < n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 0, key, n, buf, n, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} start
 * @param {Uint32Array[number]} steps
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function genChain(hashFunction, out, input, start, steps, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  for (let i = 0; i < params.n; i++) {
    out.set([input[i]], i);
  }

  for (let i = start; i < start + steps && i < params.w; i++) {
    setHashAddr(addr, i);
    hashF(hashFunction, out, out, pubSeed, addr, params.n);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {WOTSParams} wOTSParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function wOTSPKGen(hashFunction, pk, sk, wOTSParams, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  expandSeed(hashFunction, pk, sk, wOTSParams.n, wOTSParams.len);
  for (let i = 0; i < wOTSParams.len; i++) {
    setChainAddr(addr, i);
    const pkStartOffset = i * wOTSParams.n;
    genChain(
      hashFunction,
      pk.subarray(pkStartOffset, pkStartOffset + wOTSParams.n),
      pk.subarray(pkStartOffset, pkStartOffset + wOTSParams.n),
      0,
      wOTSParams.w - 1,
      wOTSParams,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} params
 * @param {Uint8Array} leaf
 * @param {Uint8Array} wotsPK
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function lTree(hashFunction, params, leaf, wotsPK, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  let l = params.len;
  const { n } = params;

  let [height] = new Uint32Array([0]);
  let [bound] = new Uint32Array([0]);

  setTreeHeight(addr, height);
  while (l > 1) {
    bound = l >>> 1;
    for (let i = 0; i < bound; i++) {
      setTreeIndex(addr, i);
      const outStartOffset = i * n;
      const inStartOffset = i * 2 * n;
      hashH(
        hashFunction,
        wotsPK.subarray(outStartOffset, outStartOffset + n),
        wotsPK.subarray(inStartOffset, inStartOffset + 2 * n),
        pubSeed,
        addr,
        n
      );
    }
    if (l % 2 === 1) {
      const destStartOffset = (l >>> 1) * n;
      const srcStartOffset = (l - 1) * n;
      for (
        let destIndex = destStartOffset, srcIndex = srcStartOffset;
        destIndex < destStartOffset + n && srcIndex < srcStartOffset + n;
        destIndex++, srcIndex++
      ) {
        wotsPK.set([wotsPK[srcIndex]], destIndex);
      }
      l = (l >>> 1) + 1;
    } else {
      l >>>= 1;
    }
    height++;
    setTreeHeight(addr, height);
  }
  leaf.set(wotsPK.subarray(0, n));
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} leaf
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} lTreeAddr
 * @param {Uint32Array} otsAddr
 */
export function genLeafWOTS(hashFunction, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr) {
  const seed = new Uint8Array(xmssParams.n);
  const pk = new Uint8Array(xmssParams.wotsParams.keySize);

  getSeed(hashFunction, seed, skSeed, xmssParams.n, otsAddr);
  wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr);
  lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} node
 * @param {Uint32Array[number]} index
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function treeHashSetup(hashFunction, node, index, bdsState, skSeed, xmssParams, pubSeed, addr) {
  const { n, h, k } = xmssParams;

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  const lastNode = index + (1 << h);

  const bound = h - k;
  const stack = new Uint8Array((h + 1) * n);
  const stackLevels = new Uint32Array(h + 1);
  let stackOffset = new Uint32Array([0])[0];
  let nodeH = new Uint32Array([0])[0];

  const bdsState1 = bdsState;
  for (let i = 0; i < bound; i++) {
    bdsState1.treeHash[i].h = i;
    bdsState1.treeHash[i].completed = 1;
    bdsState1.treeHash[i].stackUsage = 0;
  }

  for (let i = 0, index1 = index; index1 < lastNode; i++, index1++) {
    setLTreeAddr(lTreeAddr, index1);
    setOTSAddr(otsAddr, index1);

    genLeafWOTS(
      hashFunction,
      stack.subarray(stackOffset * n, stackOffset * n + n),
      skSeed,
      xmssParams,
      pubSeed,
      lTreeAddr,
      otsAddr
    );

    stackLevels.set([0], stackOffset);
    stackOffset++;
    if (h - k > 0 && i === 3) {
      bdsState1.treeHash[0].node.set(stack.subarray(stackOffset * n, stackOffset * n + n));
    }
    while (stackOffset > 1 && stackLevels[stackOffset - 1] === stackLevels[stackOffset - 2]) {
      nodeH = stackLevels[stackOffset - 1];
      if (i >>> nodeH === 1) {
        const authStart = nodeH * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let authIndex = authStart, stackIndex = stackStart;
          authIndex < authStart + n && stackIndex < stackStart + n;
          authIndex++, stackIndex++
        ) {
          bdsState1.auth.set([stack[stackIndex]], authIndex);
        }
      } else if (nodeH < h - k && i >>> nodeH === 3) {
        const stackStart = (stackOffset - 1) * n;
        bdsState1.treeHash[nodeH].node.set(stack.subarray(stackStart, stackStart + n));
      } else if (nodeH >= h - k) {
        const retainStart = ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >>> nodeH) - 3) >>> 1)) * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let retainIndex = retainStart, stackIndex = stackStart;
          retainIndex < retainStart + n && stackIndex < stackStart + n;
          retainIndex++, stackIndex++
        ) {
          bdsState1.retain.set([stack[stackIndex]], retainIndex);
        }
      }
      setTreeHeight(nodeAddr, stackLevels[stackOffset - 1]);
      setTreeIndex(nodeAddr, index1 >>> (stackLevels[stackOffset - 1] + 1));
      const stackStart = (stackOffset - 2) * n;

      hashH(
        hashFunction,
        stack.subarray(stackStart, stackStart + n),
        stack.subarray(stackStart, stackStart + 2 * n),
        pubSeed,
        nodeAddr,
        n
      );

      stackLevels[stackOffset - 2]++;
      stackOffset--;
    }
  }
  node.set(stack.subarray(0, n));
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} seed
 */
export function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
  if (xmssParams.h % 2 === 1) {
    throw new Error('Not a valid h, only even numbers supported! Try again with an even number');
  }

  const { n } = xmssParams;

  sk.set([0, 0, 0, 0]);

  const randombits = new Uint8Array(3 * n);

  shake256(randombits, seed);

  const rnd = 96;
  const pks = new Uint32Array([32])[0];
  sk.set(randombits.subarray(0, rnd), 4);
  for (let pkIndex = n, skIndex = 4 + 2 * n; pkIndex < pk.length && skIndex < 4 + 2 * n + pks; pkIndex++, skIndex++) {
    pk.set([sk[skIndex]], pkIndex);
  }

  const addr = new Uint32Array(8);
  treeHashSetup(
    hashFunction,
    pk,
    0,
    bdsState,
    sk.subarray(4, 4 + n),
    xmssParams,
    sk.subarray(4 + 2 * n, 4 + 2 * n + n),
    addr
  );

  for (let skIndex = 4 + 3 * n, pkIndex = 0; skIndex < sk.length && pkIndex < pks; skIndex++, pkIndex++) {
    sk.set([pk[pkIndex]], skIndex);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {TreeHashInst} treeHash
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function treeHashUpdate(hashFunction, treeHash, bdsState, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const treeHash1 = treeHash;
  const bdsState1 = bdsState;

  const { n } = params;

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  setLTreeAddr(lTreeAddr, treeHash1.nextIdx);
  setOTSAddr(otsAddr, treeHash1.nextIdx);

  const nodeBuffer = new Uint8Array(2 * n);
  let [nodeHeight] = new Uint32Array([0]);

  genLeafWOTS(hashFunction, nodeBuffer, skSeed, params, pubSeed, lTreeAddr, otsAddr);

  while (treeHash1.stackUsage > 0 && bdsState1.stackLevels[bdsState1.stackOffset - 1] === nodeHeight) {
    for (let i = n, j = 0; i < n + n && j < n; i++, j++) {
      nodeBuffer.set([nodeBuffer[j]], i);
    }
    const srcOffset = (bdsState1.stackOffset - 1) * n;
    for (
      let nodeIndex = 0, stackIndex = srcOffset;
      nodeIndex < n && stackIndex < srcOffset + n;
      nodeIndex++, stackIndex++
    ) {
      nodeBuffer.set([bdsState1.stack[stackIndex]], nodeIndex);
    }
    setTreeHeight(nodeAddr, nodeHeight);
    setTreeIndex(nodeAddr, treeHash1.nextIdx >>> (nodeHeight + 1));
    hashH(hashFunction, nodeBuffer.subarray(0, n), nodeBuffer, pubSeed, nodeAddr, n);
    nodeHeight++;
    treeHash1.stackUsage--;
    bdsState1.stackOffset--;
  }

  if (nodeHeight === treeHash1.h) {
    treeHash1.node.set(nodeBuffer.subarray(0, n));
    treeHash1.completed = 1;
  } else {
    const destOffset = bdsState1.stackOffset * n;
    for (
      let stackIndex = destOffset, nodeIndex = 0;
      stackIndex < destOffset + n && nodeIndex < n;
      stackIndex++, nodeIndex++
    ) {
      bdsState1.stack.set([nodeBuffer[nodeIndex]], stackIndex);
    }
    treeHash1.stackUsage++;
    bdsState1.stackLevels.set([nodeHeight], bdsState1.stackOffset);
    bdsState1.stackOffset++;
    treeHash1.nextIdx++;
  }
}

/**
 * @param {BDSState} state
 * @param {XMSSParams} params
 * @param {TreeHashInst} treeHash
 * @returns {Uint8Array[number]}
 */
export function treeHashMinHeightOnStack(state, params, treeHash) {
  let r = params.h;
  for (let i = 0; i < treeHash.stackUsage; i++) {
    const stackLevelOffset = state.stackLevels[state.stackOffset - i - 1];
    if (stackLevelOffset < r) {
      r = stackLevelOffset;
    }
  }
  return r;
}

/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} updates
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @returns {Uint32Array[number]}
 */
export function bdsTreeHashUpdate(hashFunction, bdsState, updates, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const { h, k } = params;
  let [used] = new Uint32Array([0]);
  let [lMin] = new Uint32Array([0]);
  let [level] = new Uint32Array([0]);
  let [low] = new Uint32Array([0]);

  for (let j = 0; j < updates; j++) {
    lMin = h;
    level = h - k;
    for (let i = 0; i < h - k; i++) {
      if (bdsState.treeHash[i].completed === 1) {
        low = h;
      } else if (bdsState.treeHash[i].stackUsage === 0) {
        low = i;
      } else {
        low = treeHashMinHeightOnStack(bdsState, params, bdsState.treeHash[i]);
      }
      if (low < lMin) {
        level = i;
        lMin = low;
      }
    }
    if (level === h - k) {
      break;
    }
    treeHashUpdate(hashFunction, bdsState.treeHash[level], bdsState, skSeed, params, pubSeed, addr);
    used++;
  }

  return updates - used;
}

/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function bdsRound(hashFunction, bdsState, leafIdx, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const bdsState1 = bdsState;
  const { n, h, k } = params;

  let tau = h;
  const buf = new Uint8Array(2 * n);

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  for (let i = 0; i < h; i++) {
    if ((leafIdx >>> i) % 2 === 0) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    let srcOffset = (tau - 1) * n;
    for (let bufIndex = 0, authIndex = srcOffset; bufIndex < n && authIndex < srcOffset + n; bufIndex++, authIndex++) {
      buf.set([bdsState1.auth[authIndex]], bufIndex);
    }

    srcOffset = ((tau - 1) >>> 1) * n;
    for (
      let bufIndex = n, keepIndex = srcOffset;
      bufIndex < 2 * n && keepIndex < srcOffset + n;
      bufIndex++, keepIndex++
    ) {
      buf.set([bdsState1.keep[keepIndex]], bufIndex);
    }
  }

  if (((leafIdx >>> (tau + 1)) & 1) === 0 && tau < h - 1) {
    const destOffset = (tau >>> 1) * n;
    const srcOffset = tau * n;
    for (
      let keepIndex = destOffset, authIndex = srcOffset;
      keepIndex < destOffset + n && authIndex < srcOffset + n;
      keepIndex++, authIndex++
    ) {
      bdsState1.keep.set([bdsState1.auth[authIndex]], keepIndex);
    }
  }

  if (tau === 0) {
    setLTreeAddr(lTreeAddr, leafIdx);
    setOTSAddr(otsAddr, leafIdx);
    genLeafWOTS(hashFunction, bdsState1.auth.subarray(0, n), skSeed, params, pubSeed, lTreeAddr, otsAddr);
  } else {
    setTreeHeight(nodeAddr, tau - 1);
    setTreeIndex(nodeAddr, leafIdx >>> tau);
    hashH(hashFunction, bdsState1.auth.subarray(tau * n, tau * n + n), buf, pubSeed, nodeAddr, n);
    for (let i = 0; i < tau; i++) {
      if (i < h - k) {
        for (let authIndex = i * n, nodeIndex = 0; authIndex < i * n + n && nodeIndex < n; authIndex++, nodeIndex++) {
          bdsState1.auth.set([bdsState1.treeHash[i].node[nodeIndex]], authIndex);
        }
      } else {
        const offset = (1 << (h - 1 - i)) + i - h;
        const rowIdx = ((leafIdx >>> i) - 1) >>> 1;
        const srcOffset = (offset + rowIdx) * n;
        for (
          let authIndex = i * n, retainIndex = srcOffset;
          authIndex < i * n + n && retainIndex < srcOffset + n;
          authIndex++, retainIndex++
        ) {
          bdsState1.auth.set([bdsState1.retain[retainIndex]], authIndex);
        }
      }
    }

    let compareValue = h - k;
    if (tau < h - k) {
      compareValue = tau;
    }
    for (let i = 0; i < compareValue; i++) {
      const startIdx = leafIdx + 1 + 3 * (1 << i);
      if (startIdx < 1 << h) {
        bdsState1.treeHash[i].h = i;
        bdsState1.treeHash[i].nextIdx = startIdx;
        bdsState1.treeHash[i].completed = 0;
        bdsState1.treeHash[i].stackUsage = 0;
      }
    }
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} newIdx
 * @returns {Uint32Array[number]}
 */
export function xmssFastUpdate(hashFunction, params, sk, bdsState, newIdx) {
  const [numElems] = new Uint32Array([1 << params.h]);
  const currentIdx =
    (new Uint32Array([sk[0]])[0] << 24) |
    (new Uint32Array([sk[1]])[0] << 16) |
    (new Uint32Array([sk[2]])[0] << 8) |
    new Uint32Array([sk[3]])[0];

  if (newIdx >= numElems) {
    throw new Error('Index too high');
  }
  if (newIdx < currentIdx) {
    throw new Error('Cannot rewind');
  }

  const skSeed = new Uint8Array(params.n);
  skSeed.set(sk.subarray(4, 4 + params.n));

  const startOffset = 4 + 2 * 32;
  const pubSeed = new Uint8Array(params.n);
  for (
    let pubSeedIndex = 0, skIndex = startOffset;
    pubSeedIndex < 32 && skIndex < startOffset + 32;
    pubSeedIndex++, skIndex++
  ) {
    pubSeed.set([sk[skIndex]], pubSeedIndex);
  }

  const otsAddr = new Uint32Array(8);

  for (let i = currentIdx; i < newIdx; i++) {
    if (i >= numElems) {
      return -1;
    }
    bdsRound(hashFunction, bdsState, i, skSeed, params, pubSeed, otsAddr);
    bdsTreeHashUpdate(hashFunction, bdsState, (params.h - params.k) >>> 1, skSeed, params, pubSeed, otsAddr);
  }

  sk.set(new Uint8Array([(newIdx >>> 24) & 0xff, (newIdx >>> 16) & 0xff, (newIdx >>> 8) & 0xff, newIdx & 0xff]));

  return 0;
}
