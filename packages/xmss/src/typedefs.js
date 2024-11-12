/**
 * @typedef {Object} WOTSParams
 * @property {Uint32Array[number]} len1
 * @property {Uint32Array[number]} len2
 * @property {Uint32Array[number]} len
 * @property {Uint32Array[number]} n
 * @property {Uint32Array[number]} w
 * @property {Uint32Array[number]} logW
 * @property {Uint32Array[number]} keySize
 */

/** @typedef {Uint32Array[number]} HashFunction */

/**
 * @typedef {Object} TreeHashInst
 * @property {Uint32Array[number]} h
 * @property {Uint32Array[number]} nextIdx
 * @property {Uint32Array[number]} stackUsage
 * @property {Uint8Array[number]} completed
 * @property {Uint8Array} node
 */

/**
 * @typedef {Object} BDSState
 * @property {Uint8Array} stack
 * @property {Uint32Array[number]} stackOffset
 * @property {Uint8Array} stackLevels
 * @property {Uint8Array} auth
 * @property {Uint8Array} keep
 * @property {TreeHashInst[]} treeHash
 * @property {Uint8Array} retain
 * @property {Uint32Array[number]} nextLeaf
 */

/** @typedef {Uint32Array[number]} SignatureType */

/** @typedef {Uint32Array[number]} AddrFormatType */

/**
 * @typedef {Object} QRLDescriptor
 * @property {HashFunction} hashFunction
 * @property {SignatureType} signatureType
 * @property {Uint8Array[number]} height
 * @property {AddrFormatType} addrFormatType
 * @property {() => Uint8Array[number]} getHeight
 * @property {() => HashFunction} getHashFunction
 * @property {() => SignatureType} getSignatureType
 * @property {() => AddrFormatType} getAddrFormatType
 * @property {() => Uint8Array} getBytes
 */
