/// <reference path="typedefs.js" />
import { prf } from './hash.js';
import { addrToByte, setChainAddr, setHashAddr, setKeyAndMask, setType, shake256 } from './helper.js';

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
  const stackOffset = new Uint32Array([0])[0];
  const nodeH = new Uint32Array([0])[0];

  for (let i = new Uint32Array([0])[0]; i < bound; i++) {
    bdsState.treeHash[i].h = 3;
  }

  // for i := uint32(0); i < bound; i++ {
  // 	bdsState.treeHash[i].h = i
  // 	bdsState.treeHash[i].completed = 1
  // 	bdsState.treeHash[i].stackUsage = 0
  // }
  // i := uint32(0)
  // for ; index < lastNode; index++ {
  // 	misc.SetLTreeAddr(&lTreeAddr, index)
  // 	misc.SetOTSAddr(&otsAddr, index)
  // 	genLeafWOTS(hashFunction, stack[stackOffset*n:stackOffset*n+n], skSeed, xmssParams, pubSeed, &lTreeAddr, &otsAddr)
  // 	stackLevels[stackOffset] = 0
  // 	stackOffset++
  // 	if h-k > 0 && i == 3 {
  // 		copy(bdsState.treeHash[0].node, stack[stackOffset*n:stackOffset*n+n])
  // 	}
  // 	for stackOffset > 1 && stackLevels[stackOffset-1] == stackLevels[stackOffset-2] {
  // 		nodeH = stackLevels[stackOffset-1]
  // 		if (i >> nodeH) == 1 {
  // 			authStart := nodeH * n
  // 			stackStart := (stackOffset - 1) * n
  // 			copy(bdsState.auth[authStart:authStart+n], stack[stackStart:stackStart+n])
  // 		} else {
  // 			if (nodeH < h-k) && ((i >> nodeH) == 3) {
  // 				stackStart := (stackOffset - 1) * n
  // 				copy(bdsState.treeHash[nodeH].node, stack[stackStart:stackStart+n])
  // 			} else if nodeH >= h-k {
  // 				//memcpy(state->retain + ((1 << (h - 1 - nodeh)) + nodeh - h + (((i >> nodeh) - 3) >> 1)) * n,
  // 				//	stack + (stackoffset - 1) * n, n);
  // 				retainStart := ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >> nodeH) - 3) >> 1)) * n
  // 				stackStart := (stackOffset - 1) * n
  // 				copy(bdsState.retain[retainStart:retainStart+n], stack[stackStart:stackStart+n])
  // 			}
  // 		}
  // 		misc.SetTreeHeight(&nodeAddr, stackLevels[stackOffset-1])
  // 		misc.SetTreeIndex(&nodeAddr, index>>(stackLevels[stackOffset-1]+1))
  // 		stackStart := (stackOffset - 2) * n
  // 		hashH(hashFunction, stack[stackStart:stackStart+n], stack[stackStart:stackStart+2*n], pubSeed,
  // 			&nodeAddr, n)
  // 		stackLevels[stackOffset-2]++
  // 		stackOffset--
  // 	}
  // 	i++
  // }
  // copy(node[:n], stack[:n])
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
  // treeHashSetup(hashFunction, pk, 0, bdsState, sk[4:4+n], xmssParams, sk[4+2*n:4+2*n+n], addr)
  sk.set(pk.subarray(0, pks), 4 + 3 * n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 */
export function getSeed(hashFunction, seed, skSeed, n, addr) {
  const bytes = new Uint8Array(32);

  setChainAddr(addr, 0);
  setHashAddr(addr, 0);
  setKeyAndMask(addr, 0);

  // // Generate pseudorandom value
  addrToByte(bytes, addr);
  prf(hashFunction, seed, bytes, skSeed, n);
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
  // TODO:
  // wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr)
  // lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr)
}
