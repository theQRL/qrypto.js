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

  // Generate pseudorandom value
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

  for (let j = 0; j < params.n; j++) {
    out.set([input[j]], j);
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
    bound = l >> 1;
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
      const destStartOffset = (l >> 1) * n;
      const srcStartOffset = (l - 1) * n;
      for (
        let destIndex = destStartOffset, srcIndex = srcStartOffset;
        destIndex < destStartOffset + n && srcIndex < srcStartOffset + n;
        destIndex++, srcIndex++
      ) {
        wotsPK.set([wotsPK[srcIndex]], destIndex);
      }
      l = (l >> 1) + 1;
    } else {
      l >>= 1;
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
      if (i >> nodeH === 1) {
        const authStart = nodeH * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let authIndex = authStart, stackIndex = stackStart;
          authIndex < authStart + n && stackIndex < stackStart + n;
          authIndex++, stackIndex++
        ) {
          bdsState1.auth.set([stack[stackIndex]], authIndex);
        }
      } else if (nodeH < h - k && i >> nodeH === 3) {
        const stackStart = (stackOffset - 1) * n;
        bdsState1.treeHash[nodeH].node.set(stack.subarray(stackStart, stackStart + n));
      } else if (nodeH >= h - k) {
        const retainStart = ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >> nodeH) - 3) >> 1)) * n;
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
      setTreeIndex(nodeAddr, index1 >> (stackLevels[stackOffset - 1] + 1));
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

  // Set idx = 0
  sk.set([0], 0);
  sk.set([0], 1);
  sk.set([0], 2);
  sk.set([0], 3);

  // Copy PUB_SEED to public key
  const randombits = new Uint8Array(3 * n);

  // shake256(randombits, 3 * n, seed, 48);  // FIXME: seed size has been hardcoded to 48
  shake256(randombits, seed);

  const rnd = 96;
  const pks = new Uint32Array([32])[0];
  sk.set(randombits.subarray(0, rnd), 4);
  pk.set(sk.subarray(4 + 2 * n, 4 + 2 * n + pks), n);

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

  sk.set(pk.subarray(0, pks), 4 + 3 * n);
  // TODO: complete testcases for this
}
