/// <reference path="typedefs.js" />

import { COMMON, CONSTANTS } from './constants.js';

class TreeHashInstClass {
  constructor(n = 0) {
    [this.h] = new Uint32Array([0]);
    [this.nextIdx] = new Uint32Array([0]);
    [this.stackUsage] = new Uint32Array([0]);
    [this.completed] = new Uint8Array([0]);
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
    this.keep = new Uint8Array((height >>> 1) * n);
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

class WOTSParamsClass {
  constructor(n, w) {
    this.n = n;
    this.w = w;
    [this.logW] = new Uint32Array([Math.log2(w)]);
    if (this.logW !== 2 && this.logW !== 4 && this.logW !== 8) {
      throw new Error('logW should be either 2, 4 or 8');
    }
    // an integer value is passed to the ceil function for now w.r.t. golang code. update this as and when required.
    [this.len1] = new Uint32Array([Math.ceil(parseInt(((8 * n) / this.logW).toString(), 10))]);
    [this.len2] = new Uint32Array([Math.floor(Math.log2(this.len1 * (w - 1)) / this.logW) + 1]);
    this.len = this.len1 + this.len2;
    this.keySize = this.len * n;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} w
 * @returns {WOTSParams}
 */
export function newWOTSParams(n, w) {
  return new WOTSParamsClass(n, w);
}

class XMSSParamsClass {
  constructor(n, h, w, k) {
    this.wotsParams = newWOTSParams(n, w);
    this.n = n;
    this.h = h;
    this.k = k;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint32Array[number]} w
 * @param {Uint32Array[number]} k
 * @returns {XMSSParams}
 */
export function newXMSSParams(n, h, w, k) {
  return new XMSSParamsClass(n, h, w, k);
}

class QRLDescriptorClass {
  /** @returns {Uint8Array[number]} */
  getHeight() {
    return this.height;
  }

  /** @returns {HashFunction} */
  getHashFunction() {
    return this.hashFunction;
  }

  /** @returns {SignatureType} */
  getSignatureType() {
    return this.signatureType;
  }

  /** @returns {AddrFormatType} */
  getAddrFormatType() {
    return this.addrFormatType;
  }

  /** @returns {Uint8Array} */
  getBytes() {
    const output = new Uint8Array(COMMON.DESCRIPTOR_SIZE);
    output.set([(this.signatureType << 4) | (this.hashFunction & 0x0f)], 0);
    output.set([(this.addrFormatType << 4) | ((this.height >>> 1) & 0x0f)], 1);
    return output;
  }

  constructor(hashFunction, signatureType, height, addrFormatType) {
    this.hashFunction = hashFunction;
    this.signatureType = signatureType;
    this.height = height;
    this.addrFormatType = addrFormatType;
  }
}

/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {SignatureType} signatureType
 * @param {AddrFormatType} addrFormatType
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptor(height, hashFunction, signatureType, addrFormatType) {
  return new QRLDescriptorClass(hashFunction, signatureType, height, addrFormatType);
}

/**
 * @param {Uint8Array} descriptorBytes
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromBytes(descriptorBytes) {
  if (descriptorBytes.length !== 3) {
    throw new Error('Descriptor size should be 3 bytes');
  }

  return new QRLDescriptorClass(
    descriptorBytes[0] & 0x0f,
    (descriptorBytes[0] >>> 4) & 0x0f,
    (descriptorBytes[1] & 0x0f) << 1,
    (descriptorBytes[1] & 0xf0) >>> 4
  );
}

/**
 * @param {Uint8Array} extendedSeed
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromExtendedSeed(extendedSeed) {
  if (extendedSeed.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  return newQRLDescriptorFromBytes(extendedSeed.subarray(0, COMMON.DESCRIPTOR_SIZE));
}

/**
 * @param {Uint8Array} extendedPk
 * @returns {QRLDescriptor}
 */
export function newQRLDescriptorFromExtendedPk(extendedPk) {
  if (extendedPk.length !== CONSTANTS.EXTENDED_PK_SIZE) {
    throw new Error(`extendedPk should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`);
  }

  return newQRLDescriptorFromBytes(extendedPk.subarray(0, COMMON.DESCRIPTOR_SIZE));
}
