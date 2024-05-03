'use strict';

var sha256$1 = require('@noble/hashes/sha256');
var jsSha3CommonJsPackage = require('js-sha3');

const ENDIAN = {
  LITTLE: 0,
  BIG: 1,
};

const HASH_FUNCTION = {
  SHA2_256: 0,
  SHAKE_128: 1,
  SHAKE_256: 2,
};

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 * @returns {Uint8Array}
 */
function shake128(out, msg, outStartIndex = 0, outEndIndex = out.length) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let o = outStartIndex, h = 0; o < outEndIndex; o++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], o);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 * @returns {Uint8Array}
 */
function shake256(out, msg, outStartIndex = 0, outEndIndex = out.length) {
  const hash = sha3Shake256(msg, 8 * out.length);
  for (let o = outStartIndex, h = 0; o < outEndIndex; o++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], o);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 * @returns {Uint8Array}
 */
function sha256(out, msg, outStartIndex = 0, outEndIndex = out.length) {
  const hashOut = sha256$1.sha256(msg);
  for (let o = outStartIndex, h = 0; o < outEndIndex; o++, h++) {
    out.set([hashOut[h]], o);
  }
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} typeValue
 */
function setType(addr, typeValue) {
  addr.set([typeValue], 3);
  for (let i = 4; i < 8; i++) {
    addr.set([0], i);
  }
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} lTree
 */
function setLTreeAddr(addr, lTree) {
  addr.set([lTree], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} ots
 */
function setOTSAddr(addr, ots) {
  addr.set([ots], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 */
function setChainAddr(addr, chain) {
  addr.set([chain], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 */
function setHashAddr(addr, hash) {
  addr.set([hash], 6);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 */
function setKeyAndMask(addr, keyAndMask) {
  addr.set([keyAndMask], 7);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeHeight
 */
function setTreeHeight(addr, treeHeight) {
  addr.set([treeHeight], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeIndex
 */
function setTreeIndex(addr, treeIndex) {
  addr.set([treeIndex], 6);
}

/** @returns Number */
function getEndian() {
  const buffer = new ArrayBuffer(2);
  const uint16View = new Uint16Array(buffer);
  const uint8View = new Uint8Array(buffer);
  uint16View[0] = 0xabcd;
  if (uint8View[0] === 0xcd && uint8View[1] === 0xab) {
    return ENDIAN.LITTLE;
  }
  if (uint8View[0] === 0xab && uint8View[1] === 0xcd) {
    return ENDIAN.BIG;
  }
  throw new Error('Could not determine native endian.');
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 * @param {number} outStartIndex
 */
function toByteLittleEndian(out, input, bytes, outStartIndex = 0, outEndIndex = outStartIndex + bytes - 1) {
  let inValue = input;
  for (let o = outEndIndex; o >= outStartIndex; o--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], o);
    inValue >>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 * @param {number} outStartIndex
 */
function toByteBigEndian(out, input, bytes, outStartIndex = 0, outEndIndex = outStartIndex + bytes) {
  let inValue = input;
  for (let o = outStartIndex; o < outEndIndex; o++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], o);
    inValue >>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
function addrToByte(out, addr, getEndianFunc = getEndian) {
  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        toByteLittleEndian(out, addr[i], 4, i * 4);
      }
      break;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        toByteBigEndian(out, addr[i], 4, i * 4);
      }
      break;
    default:
      throw new Error('Invalid Endian');
  }
}

/// <reference path="typedefs.js" />


/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} typeValue
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} inLen
 * @param {Uint32Array[number]} n
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 */
function coreHash(
  hashFunction,
  out,
  typeValue,
  key,
  keyLen,
  input,
  inLen,
  n,
  outStartIndex = 0,
  outEndIndex = out.length
) {
  const buf = new Uint8Array(inLen + n + keyLen);
  toByteLittleEndian(buf, typeValue, n);
  for (let i = 0; i < keyLen; i++) {
    buf.set([key[i]], i + n);
  }
  for (let i = 0; i < inLen; i++) {
    buf.set([input[i]], keyLen + n + i);
  }

  switch (hashFunction) {
    case HASH_FUNCTION.SHA2_256:
      sha256(out, buf, outStartIndex, outEndIndex);
      break;
    case HASH_FUNCTION.SHAKE_128:
      shake128(out, buf, outStartIndex, outEndIndex);
      break;
    case HASH_FUNCTION.SHAKE_256:
      shake256(out, buf, outStartIndex, outEndIndex);
      break;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {number} outStartIndex
 * @param {number} outEndIndex
 */
function prf(hashFunction, out, input, key, keyLen, outStartIndex = 0, outEndIndex = out.length) {
  coreHash(hashFunction, out, 3, key, keyLen, input, 32, keyLen, outStartIndex, outEndIndex);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 * @returns {HashHReturnType}
 */
function hashH(hashFunction, out, input, pubSeed, addr, n) {
  const buf = new Uint8Array(2 * n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(2 * n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  // Use MSB order
  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n, 0, n);
  setKeyAndMask(addr, 2);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n, n, n + n);
  for (let i = 0; i < 2 * n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 1, key, n, buf, 2 * n, n);

  return {
    hashFunction,
    out,
    input,
    pubSeed,
    addr,
    n,
  };
}

/// <reference path="typedefs.js" />

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 * @returns {GetSeedReturnType}
 */
function getSeed(hashFunction, seed, skSeed, n, addr) {
  const bytes = new Uint8Array(32);

  setChainAddr(addr, 0);
  setHashAddr(addr, 0);
  setKeyAndMask(addr, 0);

  // // Generate pseudorandom value
  addrToByte(bytes, addr);
  prf(hashFunction, seed, bytes, skSeed, n);

  return {
    hashFunction,
    seed,
    skSeed,
    n,
    addr,
  };
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} leaf
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} lTreeAddr
 * @param {Uint32Array} otsAddr
 * @returns {GenLeafWOTSReturnType}
 */
function genLeafWOTS(hashFunction, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr) {
  const seed = new Uint8Array(xmssParams.n);
  new Uint8Array(xmssParams.wotsParams.keySize);

  getSeed(hashFunction, seed, skSeed, xmssParams.n, otsAddr);
  // TODO:
  // wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr)
  // lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr)

  return {
    hashFunction,
    leaf,
    skSeed,
    xmssParams,
    pubSeed,
    lTreeAddr,
    otsAddr,
  };
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
 * @returns {TreeHashSetupReturnType}
 */
function treeHashSetup(hashFunction, node, index, bdsState, skSeed, xmssParams, pubSeed, addr) {
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

    // TODO: complete genLeafWOTS to run this function
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
          bdsState1.retain([stack[stackIndex]], retainIndex);
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

  return {
    hashFunction,
    node,
    index,
    bdsState,
    skSeed,
    xmssParams,
    pubSeed,
    addr,
  };
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} seed
 */
function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
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

  // TODO: return all parameters and write test
}

exports.ENDIAN = ENDIAN;
exports.HASH_FUNCTION = HASH_FUNCTION;
exports.XMSSFastGenKeyPair = XMSSFastGenKeyPair;
exports.addrToByte = addrToByte;
exports.coreHash = coreHash;
exports.genLeafWOTS = genLeafWOTS;
exports.getSeed = getSeed;
exports.hashH = hashH;
exports.prf = prf;
exports.setChainAddr = setChainAddr;
exports.setHashAddr = setHashAddr;
exports.setKeyAndMask = setKeyAndMask;
exports.setLTreeAddr = setLTreeAddr;
exports.setOTSAddr = setOTSAddr;
exports.setTreeHeight = setTreeHeight;
exports.setTreeIndex = setTreeIndex;
exports.setType = setType;
exports.sha256 = sha256;
exports.shake128 = shake128;
exports.shake256 = shake256;
exports.toByteLittleEndian = toByteLittleEndian;
exports.treeHashSetup = treeHashSetup;
