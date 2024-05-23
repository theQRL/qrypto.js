/// <reference path="typedefs.js" />

import { randomBytes } from '@noble/hashes/utils';
import {
  newBDSState,
  newQRLDescriptor,
  newQRLDescriptorFromExtendedPk,
  newQRLDescriptorFromExtendedSeed,
  newXMSS,
  newXMSSParams,
} from './classes.js';
import { COMMON, CONSTANTS, WOTS_PARAM } from './constants.js';
import { coreHash } from './hash.js';
import { setChainAddr, shake256, toByteLittleEndian } from './helper.js';
import { XMSSFastGenKeyPair, expandSeed, genChain } from './xmssFast.js';

/**
 * @param {Uint32Array[number]} keySize
 * @returns {Uint32Array[number]}
 */
export function calculateSignatureBaseSize(keySize) {
  return 4 + 32 + keySize;
}

/**
 * @param {XMSSParams} params
 * @returns {Uint32Array[number]}
 */
export function getSignatureSize(params) {
  const signatureBaseSize = calculateSignatureBaseSize(params.wotsParams.keySize);
  return signatureBaseSize + params.h * 32;
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} n
 * @returns {{ error: string }}
 */
export function hMsg(hashFunction, out, input, key, n) {
  if (key.length !== 3 * n) {
    return { error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.` };
  }
  coreHash(hashFunction, out, 2, key, key.length, input, input.length, n);
  return { error: null };
}

/**
 * @param {Uint8Array} output
 * @param {Uint32Array[number]} outputLen
 * @param {Uint8Array} input
 * @param {WOTSParams} params
 */
export function calcBaseW(output, outputLen, input, params) {
  let inIndex = 0;
  let outIndex = 0;
  let [total] = new Uint32Array([0]);
  let [bits] = new Uint32Array([0]);

  for (let consumed = 0; consumed < outputLen; consumed++) {
    if (bits === 0) {
      [total] = new Uint32Array([input[inIndex]]);
      inIndex++;
      [bits] = new Uint32Array([bits + 8]);
    }
    [bits] = new Uint32Array([bits - params.logW]);
    output.set([new Uint8Array([(total >> bits) & (params.w - 1)])[0]], outIndex);
    outIndex++;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint8Array} addr
 */
export function wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error(`addr should be an array of size 8`);
  }

  const baseW = new Uint8Array(params.len);
  let [csum] = new Uint32Array([0]);

  calcBaseW(baseW, params.len1, msg, params);

  for (let i = 0; i < params.len1; i++) {
    csum += params.w - 1 - new Uint32Array([baseW[i]])[0];
  }

  csum <<= 8 - ((params.len2 * params.logW) % 8);

  const len2Bytes = (params.len2 * params.logW + 7) / 8;

  const cSumBytes = new Uint8Array(len2Bytes);
  toByteLittleEndian(cSumBytes, csum, len2Bytes);

  const cSumBaseW = new Uint8Array(params.len2);

  calcBaseW(cSumBaseW, params.len2, cSumBytes, params);

  for (let i = 0; i < params.len2; i++) {
    baseW.set([cSumBaseW[i]], params.len1 + i);
  }

  expandSeed(hashFunction, sig, sk, params.n, params.len);

  for (let i = 0; i < params.len; i++) {
    setChainAddr(addr, i);
    const offset = i * params.n;
    genChain(
      hashFunction,
      sig.subarray(offset, offset + params.n),
      sig.subarray(offset, offset + params.n),
      0,
      new Uint32Array([baseW[i]])[0],
      params,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {QRLDescriptor} desc
 * @param {Uint8Array} seed
 * @returns {XMSS}
 */
export function initializeTree(desc, seed) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }

  const [height] = new Uint32Array([desc.getHeight()]);
  const hashFunction = desc.getHashFunction();
  const sk = new Uint8Array(132);
  const pk = new Uint8Array(64);

  const k = WOTS_PARAM.K;
  const w = WOTS_PARAM.W;
  const n = WOTS_PARAM.N;

  if (k >= height || (height - k) % 2 === 1) {
    throw new Error('For BDS traversal, H - K must be even, with H > K >= 2!');
  }

  const xmssParams = newXMSSParams(n, height, w, k);
  const bdsState = newBDSState(height, n, k);
  XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed);

  return newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc);
}

/**
 * @param {Uint8Array} seed
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {AddrFormatType} addrFormatType
 * @returns {XMSS}
 */
export function newXMSSFromSeed(seed, height, hashFunction, addrFormatType) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }

  const signatureType = COMMON.XMSS_SIG;
  if (height > CONSTANTS.MAX_HEIGHT) {
    throw new Error('Height should be <= 254');
  }
  const desc = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);

  return initializeTree(desc, seed);
}

/**
 * @param {Uint8Array} extendedSeed
 * @returns {XMSS}
 */
export function newXMSSFromExtendedSeed(extendedSeed) {
  if (extendedSeed.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  const desc = newQRLDescriptorFromExtendedSeed(extendedSeed);
  const seed = new Uint8Array(COMMON.SEED_SIZE);
  seed.set(extendedSeed.subarray(COMMON.DESCRIPTOR_SIZE));

  return initializeTree(desc, seed);
}

/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @returns {XMSS}
 */
export function newXMSSFromHeight(height, hashFunction) {
  const seed = randomBytes(COMMON.SEED_SIZE);

  return newXMSSFromSeed(seed, height, hashFunction, COMMON.SHA256_2X);
}

/**
 * @param {Uint8Array} ePK
 * @returns {Uint8Array}
 */
export function getXMSSAddressFromPK(ePK) {
  const desc = newQRLDescriptorFromExtendedPk(ePK);

  if (desc.getAddrFormatType() !== COMMON.SHA256_2X) {
    throw new Error('Address format type not supported');
  }

  const address = new Uint8Array(COMMON.ADDRESS_SIZE);
  const descBytes = desc.getBytes();

  for (
    let addressIndex = 0, descBytesIndex = 0;
    addressIndex < COMMON.DESCRIPTOR_SIZE && descBytesIndex < descBytes.length;
    addressIndex++, descBytesIndex++
  ) {
    address.set([descBytes[descBytesIndex]], addressIndex);
  }

  const hashedKey = new Uint8Array(32);
  shake256(hashedKey, ePK);

  for (
    let addressIndex = COMMON.DESCRIPTOR_SIZE,
      hashedKeyIndex = hashedKey.length - COMMON.ADDRESS_SIZE + COMMON.DESCRIPTOR_SIZE;
    addressIndex < address.length && hashedKeyIndex < hashedKey.length;
    addressIndex++, hashedKeyIndex++
  ) {
    address.set([hashedKey[hashedKeyIndex]], addressIndex);
  }

  return address;
}
