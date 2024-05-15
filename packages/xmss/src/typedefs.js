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

/**
 * @typedef {Object} XMSSParams
 * @property {WOTSParams} wotsParams
 * @property {Uint32Array[number]} n
 * @property {Uint32Array[number]} h
 * @property {Uint32Array[number]} k
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
 * @property {function():Uint8Array[number]} getHeight
 * @property {function():HashFunction} getHashFunction
 * @property {function():SignatureType} getSignatureType
 * @property {function():AddrFormatType} getAddrFormatType
 * @property {function():Uint8Array} getBytes
 */

/**
 * @typedef {Object} XMSS
 * @property {XMSSParams} xmssParams
 * @property {HashFunction} hashFunction
 * @property {Uint8Array[number]} height
 * @property {Uint8Array} sk
 * @property {Uint8Array} seed
 * @property {BDSState} bdsState
 * @property {QRLDescriptor} desc
 */
