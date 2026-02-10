'use strict';

const Shake128Rate = 168;
const Shake256Rate = 136;
const Stream128BlockBytes = Shake128Rate;
const Stream256BlockBytes = Shake256Rate;

const SeedBytes = 32;
const CRHBytes = 64;
const TRBytes = 64;
const RNDBytes = 32;
const N = 256;
const Q = 8380417;
const QInv = 58728449;
const D = 13;

const K = 8;
const L = 7;
const ETA = 2;
const TAU = 60;
const BETA = 120;
const GAMMA1 = 1 << 19;
const GAMMA2 = Math.floor((Q - 1) / 32);
const OMEGA = 75;
const CTILDEBytes = 64;

const PolyT1PackedBytes = 320;
const PolyT0PackedBytes = 416;
const PolyETAPackedBytes = 96;
const PolyZPackedBytes = 640;
const PolyVecHPackedBytes = OMEGA + K;
const PolyW1PackedBytes = 128;

const CryptoPublicKeyBytes = SeedBytes + K * PolyT1PackedBytes;
const CryptoSecretKeyBytes =
  2 * SeedBytes + TRBytes + L * PolyETAPackedBytes + K * PolyETAPackedBytes + K * PolyT0PackedBytes;
const CryptoBytes = CTILDEBytes + L * PolyZPackedBytes + PolyVecHPackedBytes;

const PolyUniformNBlocks = Math.floor((768 + Stream128BlockBytes - 1) / Stream128BlockBytes);
const PolyUniformETANBlocks = Math.floor((136 + Stream256BlockBytes - 1) / Stream256BlockBytes);
const PolyUniformGamma1NBlocks = Math.floor((PolyZPackedBytes + Stream256BlockBytes - 1) / Stream256BlockBytes);

const zetas = [
  0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251, -2091905, 3119733, -2884855,
  3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549, -2118186, -3859737,
  -1399561, -3277672, 1757237, -19422, 4010497, 280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516,
  3915439, -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
  -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598, -1000202,
  -3190144, -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
  -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992, 44288,
  -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856, 189548, -3553272,
  3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669, -1584928, -812732, -1439742, -3019102, -3881060,
  -3628969, 3839961, 2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439,
  -1235728, 3513181, -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
  -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297, 286988, -2437823, 4108315,
  3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016,
  1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100,
  1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
  -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455, -164721, 1957272,
  3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107, -3038916, 3523897,
  3866901, 269760, 2213111, -975884, 1717735, 472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646,
  -3833893, -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
  -1362209, 3937738, 1400424, -846154, 1976782,
];

/**
 * Internal helpers for u64. BigUint64Array is too slow as per 2025, so we implement it using Uint32Array.
 * @todo re-check https://issues.chromium.org/issues/42212588
 * @module
 */
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));

/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is positive integer. */
function anumber(n, title = '') {
    if (!Number.isSafeInteger(n) || n < 0) {
        const prefix = title && `"${title}" `;
        throw new Error(`${prefix}expected integer >= 0, got ${n}`);
    }
}
/** Asserts something is Uint8Array. */
function abytes(value, length, title = '') {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== undefined;
    if (!bytes || (needsLen)) {
        const prefix = title && `"${title}" `;
        const ofLen = '';
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        throw new Error(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
    }
    return value;
}
/** Asserts a hash instance has not been destroyed / finished */
function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/** Asserts output is properly-sized byte array */
function aoutput(out, instance) {
    abytes(out, undefined, 'digestInto() output');
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('"digestInto() output" expected to be of length >=' + min);
    }
}
/** Cast u8 / u16 / u32 to u32. */
function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
const isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
/** The byte swap operation for uint32 */
function byteSwap(word) {
    return (((word << 24) & 0xff000000) |
        ((word << 8) & 0xff0000) |
        ((word >>> 8) & 0xff00) |
        ((word >>> 24) & 0xff));
}
/** In place byte swap for Uint32Array */
function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap(arr[i]);
    }
    return arr;
}
const swap32IfBE = isLE
    ? (u) => u
    : byteSwap32;
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin = /* @__PURE__ */ (() => 
// @ts-ignore
typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0; // '2' => 50-48
    if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
    return;
}
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes$1(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // @ts-ignore
    if (hasHexBuiltin)
        return Uint8Array.fromHex(hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
/** Creates function with outputLen, blockLen, create properties from a class constructor. */
function createHasher(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(undefined);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
}
/** Creates OID opts for NIST hashes, with prefix 06 09 60 86 48 01 65 03 04 02. */
const oidNist = (suffix) => ({
    oid: Uint8Array.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix]),
});

/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out [FIPS-202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
 * [Website](https://keccak.team/keccak.html),
 * [the differences between SHA-3 and Keccak](https://crypto.stackexchange.com/questions/15727/what-are-the-key-differences-between-the-draft-sha-3-standard-and-the-keccak-sub).
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */
// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
const SHA3_PI = [];
const SHA3_ROTL = [];
const _SHA3_IOTA = []; // no pure annotation: var is always used
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    // Pi
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
    // Iota
    let t = _0n;
    for (let j = 0; j < 7; j++) {
        R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
        if (R & _2n)
            t ^= _1n << ((_1n << BigInt(j)) - _1n);
    }
    _SHA3_IOTA.push(t);
}
const IOTAS = split(_SHA3_IOTA, true);
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];
// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s) => (s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s));
const rotlL = (h, l, s) => (s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s));
/** `keccakf1600` internal function, additionally allows to adjust round count. */
function keccakP(s, rounds = 24) {
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
        // Theta θ
        for (let x = 0; x < 10; x++)
            B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        for (let x = 0; x < 10; x += 2) {
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
            for (let y = 0; y < 50; y += 10) {
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for (let t = 0; t < 24; t++) {
            const shift = SHA3_ROTL[t];
            const Th = rotlH(curH, curL, shift);
            const Tl = rotlL(curH, curL, shift);
            const PI = SHA3_PI[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        for (let y = 0; y < 50; y += 10) {
            for (let x = 0; x < 10; x++)
                B[x] = s[y + x];
            for (let x = 0; x < 10; x++)
                s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H[round];
        s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
}
/** Keccak sponge function. */
class Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.rounds = rounds;
        // Can be passed from user as dkLen
        anumber(outputLen, 'outputLen');
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        // 0 < blockLen < 200
        if (!(0 < blockLen && blockLen < 200))
            throw new Error('only keccak-f1600 function is supported');
        this.state = new Uint8Array(200);
        this.state32 = u32(this.state);
    }
    clone() {
        return this._cloneInto();
    }
    keccak() {
        swap32IfBE(this.state32);
        keccakP(this.state32, this.rounds);
        swap32IfBE(this.state32);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        aexists(this);
        abytes(data);
        const { blockLen, state } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
                state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
                this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished)
            return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // Do the padding
        state[pos] ^= suffix;
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1)
            this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        aexists(this, false);
        abytes(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len;) {
            if (this.posOut >= blockLen)
                this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
        if (!this.enableXOF)
            throw new Error('XOF is not possible for this instance');
        return this.writeInto(out);
    }
    xof(bytes) {
        anumber(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        aoutput(out, this);
        if (this.finished)
            throw new Error('digest() was already called');
        this.writeInto(out);
        this.destroy();
        return out;
    }
    digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
        this.destroyed = true;
        clean(this.state);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        to.destroyed = this.destroyed;
        return to;
    }
}
const genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true), info);
/** SHAKE128 XOF with 128-bit security. */
const shake128 = 
/* @__PURE__ */
genShake(0x1f, 168, 16, /* @__PURE__ */ oidNist(0x0b));
/** SHAKE256 XOF with 256-bit security. */
const shake256 = 
/* @__PURE__ */
genShake(0x1f, 136, 32, /* @__PURE__ */ oidNist(0x0c));

/**
 * FIPS 202 SHAKE functions using @noble/hashes
 * Provides streaming XOF (extendable output function) interface
 */


/**
 * Keccak state wrapper for @noble/hashes
 * Maintains hasher instance for streaming operations
 */
class KeccakState {
  constructor() {
    this.hasher = null;
    this.finalized = false;
  }
}

// SHAKE-128 functions

function shake128Init(state) {
  state.hasher = shake128.create({});
  state.finalized = false;
}

function shake128Absorb(state, input) {
  state.hasher.update(input);
}

function shake128Finalize(state) {
  // Mark as finalized - actual finalization happens on first xofInto call
  state.finalized = true;
}

function shake128SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake128Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}

// SHAKE-256 functions

function shake256Init(state) {
  state.hasher = shake256.create({});
  state.finalized = false;
}

function shake256Absorb(state, input) {
  state.hasher.update(input);
}

function shake256Finalize(state) {
  // Mark as finalized - actual finalization happens on first xofInto call
  state.finalized = true;
}

function shake256SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake256Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}

function mldsaShake128StreamInit(state, seed, nonce) {
  if (seed.length !== SeedBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${SeedBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake128Init(state);
  shake128Absorb(state, seed);
  shake128Absorb(state, t);
  shake128Finalize(state);
}

function mldsaShake256StreamInit(state, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${CRHBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Absorb(state, t);
  shake256Finalize(state);
}

function montgomeryReduce(a) {
  let t = BigInt.asIntN(32, BigInt.asIntN(64, BigInt.asIntN(32, a)) * BigInt(QInv));
  t = BigInt.asIntN(32, (a - t * BigInt(Q)) >> 32n);
  return t;
}

function reduce32(a) {
  let t = (a + (1 << 22)) >> 23;
  t = a - t * Q;
  return t;
}

function cAddQ(a) {
  let ar = a;
  ar += (ar >> 31) & Q;
  return ar;
}

function ntt(a) {
  let k = 0;
  let j = 0;

  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = zetas[++k];
      for (j = start; j < start + len; ++j) {
        const t = Number(montgomeryReduce(BigInt.asIntN(64, BigInt(zeta) * BigInt(a[j + len]))));
        a[j + len] = a[j] - t;
        a[j] += t;
      }
    }
  }
}

function invNTTToMont(a) {
  const f = 41978n; // mont^2/256
  let j = 0;
  let k = 256;

  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = BigInt.asIntN(32, BigInt(-zetas[--k]));
      for (j = start; j < start + len; ++j) {
        const t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = Number(montgomeryReduce(BigInt.asIntN(64, zeta * BigInt(a[j + len]))));
      }
    }
  }
  for (let j = 0; j < N; ++j) {
    a[j] = Number(montgomeryReduce(BigInt.asIntN(64, f * BigInt(a[j]))));
  }
}

function power2round(a0p, i, a) {
  const a0 = a0p;
  const a1 = (a + (1 << (D - 1)) - 1) >> D;
  a0[i] = a - (a1 << D);
  return a1;
}

function decompose(a0p, i, a) {
  const a0 = a0p;
  let a1 = (a + 127) >> 7;
  a1 = (a1 * 1025 + (1 << 21)) >> 22;
  a1 &= 15;

  a0[i] = a - a1 * 2 * GAMMA2;
  a0[i] -= (((Q - 1) / 2 - a0[i]) >> 31) & Q;
  return a1;
}

function makeHint(a0, a1) {
  if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 === -GAMMA2 && a1 !== 0)) return 1;

  return 0;
}

function useHint(a, hint) {
  const a0 = new Int32Array(1);
  const a1 = decompose(a0, 0, a);

  if (hint === 0) return a1;

  if (a0[0] > 0) return (a1 + 1) & 15;
  return (a1 - 1) & 15;
}

class Poly {
  constructor() {
    this.coeffs = new Int32Array(N);
  }

  copy(poly) {
    for (let i = N - 1; i >= 0; i--) {
      this.coeffs[i] = poly.coeffs[i];
    }
  }
}

function polyReduce(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = reduce32(a.coeffs[i]);
}

function polyCAddQ(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = cAddQ(a.coeffs[i]);
}

function polyAdd(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
}

function polySub(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
}

function polyShiftL(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] <<= D;
}

function polyNTT(a) {
  ntt(a.coeffs);
}

function polyInvNTTToMont(a) {
  invNTTToMont(a.coeffs);
}

function polyPointWiseMontgomery(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = Number(montgomeryReduce(BigInt(a.coeffs[i]) * BigInt(b.coeffs[i])));
}

function polyPower2round(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = power2round(a0.coeffs, i, a.coeffs[i]);
}

function polyDecompose(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = decompose(a0.coeffs, i, a.coeffs[i]);
}

function polyMakeHint(hp, a0, a1) {
  let s = 0;
  const h = hp;
  for (let i = 0; i < N; ++i) {
    h.coeffs[i] = makeHint(a0.coeffs[i], a1.coeffs[i]);
    s += h.coeffs[i];
  }

  return s;
}

function polyUseHint(bp, a, h) {
  const b = bp;
  for (let i = 0; i < N; ++i) {
    b.coeffs[i] = useHint(a.coeffs[i], h.coeffs[i]);
  }
}

function polyChkNorm(a, b) {
  if (b > Math.floor((Q - 1) / 8)) {
    return 1;
  }

  for (let i = 0; i < N; i++) {
    let t = a.coeffs[i] >> 31;
    t = a.coeffs[i] - (t & (2 * a.coeffs[i]));

    if (t >= b) {
      return 1;
    }
  }

  return 0;
}

function rejUniform(ap, aOffset, len, buf, bufLen) {
  let ctr = 0;
  let pos = 0;
  const a = ap;
  while (ctr < len && pos + 3 <= bufLen) {
    let t = buf[pos++];
    t |= buf[pos++] << 8;
    t |= buf[pos++] << 16;
    t &= 0x7fffff;

    if (t < Q) {
      a[aOffset + ctr++] = t;
    }
  }

  return ctr;
}

function polyUniform(a, seed, nonce) {
  let off = 0;
  let bufLen = PolyUniformNBlocks * Stream128BlockBytes;
  const buf = new Uint8Array(PolyUniformNBlocks * Stream128BlockBytes + 2);

  const state = new KeccakState();
  mldsaShake128StreamInit(state, seed, nonce);
  shake128SqueezeBlocks(buf, off, PolyUniformNBlocks, state);

  let ctr = rejUniform(a.coeffs, 0, N, buf, bufLen);

  // Note: With current parameters, needing extra blocks is vanishingly unlikely.
  /* c8 ignore start */
  while (ctr < N) {
    off = bufLen % 3;
    for (let i = 0; i < off; ++i) buf[i] = buf[bufLen - off + i];

    shake128SqueezeBlocks(buf, off, 1, state);
    bufLen = Stream128BlockBytes + off;
    ctr += rejUniform(a.coeffs, ctr, N - ctr, buf, bufLen);
  }
  /* c8 ignore stop */
}

function rejEta(aP, aOffset, len, buf, bufLen) {
  let ctr;
  let pos;
  let t0;
  let t1;
  const a = aP;
  ctr = 0;
  pos = 0;
  while (ctr < len && pos < bufLen) {
    t0 = buf[pos] & 0x0f;
    t1 = buf[pos++] >> 4;

    if (t0 < 15) {
      t0 -= ((205 * t0) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t0;
    }
    if (t1 < 15 && ctr < len) {
      t1 -= ((205 * t1) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t1;
    }
  }

  return ctr;
}

function polyUniformEta(a, seed, nonce) {
  let ctr;
  const bufLen = PolyUniformETANBlocks * Stream256BlockBytes;
  const buf = new Uint8Array(bufLen);

  const state = new KeccakState();
  mldsaShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformETANBlocks, state);

  ctr = rejEta(a.coeffs, 0, N, buf, bufLen);
  while (ctr < N) {
    shake256SqueezeBlocks(buf, 0, 1, state);
    ctr += rejEta(a.coeffs, ctr, N - ctr, buf, Stream256BlockBytes);
  }
}

function polyZUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r.coeffs[2 * i] = a[aOffset + 5 * i];
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 1] << 8;
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 2] << 16;
    r.coeffs[2 * i] &= 0xfffff;

    r.coeffs[2 * i + 1] = a[aOffset + 5 * i + 2] >> 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 3] << 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 4] << 12;
    r.coeffs[2 * i + 1] &= 0xfffff;

    r.coeffs[2 * i] = GAMMA1 - r.coeffs[2 * i];
    r.coeffs[2 * i + 1] = GAMMA1 - r.coeffs[2 * i + 1];
  }
}

function polyUniformGamma1(a, seed, nonce) {
  const buf = new Uint8Array(PolyUniformGamma1NBlocks * Stream256BlockBytes);

  const state = new KeccakState();
  mldsaShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformGamma1NBlocks, state);
  polyZUnpack(a, buf, 0);
}

function polyChallenge(cP, seed) {
  if (seed.length !== CTILDEBytes) throw new Error('invalid ctilde length');

  let b;
  let pos;
  const c = cP;
  const buf = new Uint8Array(Shake256Rate);

  const state = new KeccakState();
  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Finalize(state);
  shake256SqueezeBlocks(buf, 0, 1, state);

  let signs = 0n;
  for (let i = 0; i < 8; ++i) {
    signs = BigInt.asUintN(64, signs | (BigInt(buf[i]) << BigInt(8 * i)));
  }
  pos = 8;

  for (let i = 0; i < N; ++i) {
    c.coeffs[i] = 0;
  }
  for (let i = N - TAU; i < N; ++i) {
    do {
      // Note: Re-squeezing here is extremely unlikely with TAU=60.
      /* c8 ignore start */
      if (pos >= Shake256Rate) {
        shake256SqueezeBlocks(buf, 0, 1, state);
        pos = 0;
      }
      /* c8 ignore stop */

      b = buf[pos++];
    } while (b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = Number(1n - 2n * (signs & 1n));
    signs >>= 1n;
  }
}

function polyEtaPack(rP, rOffset, a) {
  const t = new Uint8Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = ETA - a.coeffs[8 * i];
    t[1] = ETA - a.coeffs[8 * i + 1];
    t[2] = ETA - a.coeffs[8 * i + 2];
    t[3] = ETA - a.coeffs[8 * i + 3];
    t[4] = ETA - a.coeffs[8 * i + 4];
    t[5] = ETA - a.coeffs[8 * i + 5];
    t[6] = ETA - a.coeffs[8 * i + 6];
    t[7] = ETA - a.coeffs[8 * i + 7];

    r[rOffset + 3 * i] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[rOffset + 3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[rOffset + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
}

function polyEtaUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = (a[aOffset + 3 * i] >> 0) & 7;
    r.coeffs[8 * i + 1] = (a[aOffset + 3 * i] >> 3) & 7;
    r.coeffs[8 * i + 2] = ((a[aOffset + 3 * i] >> 6) | (a[aOffset + 3 * i + 1] << 2)) & 7;
    r.coeffs[8 * i + 3] = (a[aOffset + 3 * i + 1] >> 1) & 7;
    r.coeffs[8 * i + 4] = (a[aOffset + 3 * i + 1] >> 4) & 7;
    r.coeffs[8 * i + 5] = ((a[aOffset + 3 * i + 1] >> 7) | (a[aOffset + 3 * i + 2] << 1)) & 7;
    r.coeffs[8 * i + 6] = (a[aOffset + 3 * i + 2] >> 2) & 7;
    r.coeffs[8 * i + 7] = (a[aOffset + 3 * i + 2] >> 5) & 7;

    r.coeffs[8 * i] = ETA - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = ETA - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = ETA - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = ETA - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = ETA - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = ETA - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = ETA - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = ETA - r.coeffs[8 * i + 7];
  }
}

function polyT1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r[rOffset + 5 * i] = a.coeffs[4 * i] >> 0;
    r[rOffset + 5 * i + 1] = (a.coeffs[4 * i] >> 8) | (a.coeffs[4 * i + 1] << 2);
    r[rOffset + 5 * i + 2] = (a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4);
    r[rOffset + 5 * i + 3] = (a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6);
    r[rOffset + 5 * i + 4] = a.coeffs[4 * i + 3] >> 2;
  }
}

function polyT1Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r.coeffs[4 * i] = ((a[aOffset + 5 * i] >> 0) | (a[aOffset + 5 * i + 1] << 8)) & 0x3ff;
    r.coeffs[4 * i + 1] = ((a[aOffset + 5 * i + 1] >> 2) | (a[aOffset + 5 * i + 2] << 6)) & 0x3ff;
    r.coeffs[4 * i + 2] = ((a[aOffset + 5 * i + 2] >> 4) | (a[aOffset + 5 * i + 3] << 4)) & 0x3ff;
    r.coeffs[4 * i + 3] = ((a[aOffset + 5 * i + 3] >> 6) | (a[aOffset + 5 * i + 4] << 2)) & 0x3ff;
  }
}

function polyT0Pack(rP, rOffset, a) {
  const t = new Uint32Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = (1 << (D - 1)) - a.coeffs[8 * i];
    t[1] = (1 << (D - 1)) - a.coeffs[8 * i + 1];
    t[2] = (1 << (D - 1)) - a.coeffs[8 * i + 2];
    t[3] = (1 << (D - 1)) - a.coeffs[8 * i + 3];
    t[4] = (1 << (D - 1)) - a.coeffs[8 * i + 4];
    t[5] = (1 << (D - 1)) - a.coeffs[8 * i + 5];
    t[6] = (1 << (D - 1)) - a.coeffs[8 * i + 6];
    t[7] = (1 << (D - 1)) - a.coeffs[8 * i + 7];

    r[rOffset + 13 * i] = t[0];
    r[rOffset + 13 * i + 1] = t[0] >> 8;
    r[rOffset + 13 * i + 1] |= t[1] << 5;
    r[rOffset + 13 * i + 2] = t[1] >> 3;
    r[rOffset + 13 * i + 3] = t[1] >> 11;
    r[rOffset + 13 * i + 3] |= t[2] << 2;
    r[rOffset + 13 * i + 4] = t[2] >> 6;
    r[rOffset + 13 * i + 4] |= t[3] << 7;
    r[rOffset + 13 * i + 5] = t[3] >> 1;
    r[rOffset + 13 * i + 6] = t[3] >> 9;
    r[rOffset + 13 * i + 6] |= t[4] << 4;
    r[rOffset + 13 * i + 7] = t[4] >> 4;
    r[rOffset + 13 * i + 8] = t[4] >> 12;
    r[rOffset + 13 * i + 8] |= t[5] << 1;
    r[rOffset + 13 * i + 9] = t[5] >> 7;
    r[rOffset + 13 * i + 9] |= t[6] << 6;
    r[rOffset + 13 * i + 10] = t[6] >> 2;
    r[rOffset + 13 * i + 11] = t[6] >> 10;
    r[rOffset + 13 * i + 11] |= t[7] << 3;
    r[rOffset + 13 * i + 12] = t[7] >> 5;
  }
}

function polyT0Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = a[aOffset + 13 * i];
    r.coeffs[8 * i] |= a[aOffset + 13 * i + 1] << 8;
    r.coeffs[8 * i] &= 0x1fff;

    r.coeffs[8 * i + 1] = a[aOffset + 13 * i + 1] >> 5;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 2] << 3;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 3] << 11;
    r.coeffs[8 * i + 1] &= 0x1fff;

    r.coeffs[8 * i + 2] = a[aOffset + 13 * i + 3] >> 2;
    r.coeffs[8 * i + 2] |= a[aOffset + 13 * i + 4] << 6;
    r.coeffs[8 * i + 2] &= 0x1fff;

    r.coeffs[8 * i + 3] = a[aOffset + 13 * i + 4] >> 7;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 5] << 1;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 6] << 9;
    r.coeffs[8 * i + 3] &= 0x1fff;

    r.coeffs[8 * i + 4] = a[aOffset + 13 * i + 6] >> 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 7] << 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 8] << 12;
    r.coeffs[8 * i + 4] &= 0x1fff;

    r.coeffs[8 * i + 5] = a[aOffset + 13 * i + 8] >> 1;
    r.coeffs[8 * i + 5] |= a[aOffset + 13 * i + 9] << 7;
    r.coeffs[8 * i + 5] &= 0x1fff;

    r.coeffs[8 * i + 6] = a[aOffset + 13 * i + 9] >> 6;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 10] << 2;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 11] << 10;
    r.coeffs[8 * i + 6] &= 0x1fff;

    r.coeffs[8 * i + 7] = a[aOffset + 13 * i + 11] >> 3;
    r.coeffs[8 * i + 7] |= a[aOffset + 13 * i + 12] << 5;
    r.coeffs[8 * i + 7] &= 0x1fff;

    r.coeffs[8 * i] = (1 << (D - 1)) - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = (1 << (D - 1)) - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = (1 << (D - 1)) - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = (1 << (D - 1)) - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = (1 << (D - 1)) - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = (1 << (D - 1)) - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = (1 << (D - 1)) - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = (1 << (D - 1)) - r.coeffs[8 * i + 7];
  }
}

function polyZPack(rP, rOffset, a) {
  const t = new Uint32Array(4);
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    t[0] = GAMMA1 - a.coeffs[2 * i];
    t[1] = GAMMA1 - a.coeffs[2 * i + 1];

    r[rOffset + 5 * i] = t[0];
    r[rOffset + 5 * i + 1] = t[0] >> 8;
    r[rOffset + 5 * i + 2] = t[0] >> 16;
    r[rOffset + 5 * i + 2] |= t[1] << 4;
    r[rOffset + 5 * i + 3] = t[1] >> 4;
    r[rOffset + 5 * i + 4] = t[1] >> 12;
  }
}

function polyW1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r[rOffset + i] = a.coeffs[2 * i] | (a.coeffs[2 * i + 1] << 4);
  }
}

class PolyVecK {
  constructor() {
    this.vec = new Array(K).fill().map(() => new Poly());
  }
}

class PolyVecL {
  constructor() {
    this.vec = new Array(L).fill().map(() => new Poly());
  }

  copy(polyVecL) {
    for (let i = L - 1; i >= 0; i--) {
      this.vec[i].copy(polyVecL.vec[i]);
    }
  }
}

function polyVecMatrixExpand(mat, rho) {
  if (rho.length !== SeedBytes) {
    throw new Error(`invalid rho length ${rho.length} | Expected length ${SeedBytes}`);
  }
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < L; ++j) {
      polyUniform(mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

function polyVecMatrixPointWiseMontgomery(t, mat, v) {
  for (let i = 0; i < K; ++i) {
    polyVecLPointWiseAccMontgomery(t.vec[i], mat[i], v);
  }
}

function polyVecLUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecLUniformGamma1(v, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformGamma1(v.vec[i], seed, L * nonce + i);
  }
}

function polyVecLReduce(v) {
  for (let i = 0; i < L; i++) {
    polyReduce(v.vec[i]);
  }
}

function polyVecLAdd(w, u, v) {
  for (let i = 0; i < L; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecLNTT(v) {
  for (let i = 0; i < L; ++i) {
    polyNTT(v.vec[i]);
  }
}

function polyVecLInvNTTToMont(v) {
  for (let i = 0; i < L; ++i) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecLPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < L; ++i) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecLPointWiseAccMontgomery(w, u, v) {
  const t = new Poly();
  polyPointWiseMontgomery(w, u.vec[0], v.vec[0]);
  for (let i = 1; i < L; i++) {
    polyPointWiseMontgomery(t, u.vec[i], v.vec[i]);
    polyAdd(w, w, t);
  }
}

function polyVecLChkNorm(v, bound) {
  for (let i = 0; i < L; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  for (let i = 0; i < K; ++i) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecKReduce(v) {
  for (let i = 0; i < K; ++i) {
    polyReduce(v.vec[i]);
  }
}

function polyVecKCAddQ(v) {
  for (let i = 0; i < K; ++i) {
    polyCAddQ(v.vec[i]);
  }
}

function polyVecKAdd(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKSub(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polySub(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKShiftL(v) {
  for (let i = 0; i < K; ++i) {
    polyShiftL(v.vec[i]);
  }
}

function polyVecKNTT(v) {
  for (let i = 0; i < K; i++) {
    polyNTT(v.vec[i]);
  }
}

function polyVecKInvNTTToMont(v) {
  for (let i = 0; i < K; i++) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecKPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < K; i++) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecKChkNorm(v, bound) {
  for (let i = 0; i < K; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKPower2round(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyPower2round(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKDecompose(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyDecompose(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKMakeHint(h, v0, v1) {
  let s = 0;
  for (let i = 0; i < K; i++) {
    s += polyMakeHint(h.vec[i], v0.vec[i], v1.vec[i]);
  }
  return s;
}

function polyVecKUseHint(w, u, h) {
  for (let i = 0; i < K; ++i) {
    polyUseHint(w.vec[i], u.vec[i], h.vec[i]);
  }
}

function polyVecKPackW1(r, w1) {
  for (let i = 0; i < K; ++i) {
    polyW1Pack(r, i * PolyW1PackedBytes, w1.vec[i]);
  }
}

function packPk(pkp, rho, t1) {
  const pk = pkp;
  for (let i = 0; i < SeedBytes; ++i) {
    pk[i] = rho[i];
  }
  for (let i = 0; i < K; ++i) {
    polyT1Pack(pk, SeedBytes + i * PolyT1PackedBytes, t1.vec[i]);
  }
}

function unpackPk(rhop, t1, pk) {
  const rho = rhop;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = pk[i];
  }

  for (let i = 0; i < K; ++i) {
    polyT1Unpack(t1.vec[i], pk, SeedBytes + i * PolyT1PackedBytes);
  }
}

function packSk(skp, rho, tr, key, t0, s1, s2) {
  let skOffset = 0;
  const sk = skp;
  for (let i = 0; i < SeedBytes; ++i) {
    sk[i] = rho[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    sk[skOffset + i] = key[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < TRBytes; ++i) {
    sk[skOffset + i] = tr[i];
  }
  skOffset += TRBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s1.vec[i]);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s2.vec[i]);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Pack(sk, skOffset + i * PolyT0PackedBytes, t0.vec[i]);
  }
}

function unpackSk(rhoP, trP, keyP, t0, s1, s2, sk) {
  let skOffset = 0;
  const rho = rhoP;
  const tr = trP;
  const key = keyP;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = sk[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    key[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < TRBytes; ++i) {
    tr[i] = sk[skOffset + i];
  }
  skOffset += TRBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaUnpack(s1.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaUnpack(s2.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Unpack(t0.vec[i], sk, skOffset + i * PolyT0PackedBytes);
  }
}

function packSig(sigP, ctilde, z, h) {
  let sigOffset = 0;
  const sig = sigP;
  for (let i = 0; i < CTILDEBytes; ++i) {
    sig[i] = ctilde[i];
  }
  sigOffset += CTILDEBytes;

  for (let i = 0; i < L; ++i) {
    polyZPack(sig, sigOffset + i * PolyZPackedBytes, z.vec[i]);
  }
  sigOffset += L * PolyZPackedBytes;

  for (let i = 0; i < OMEGA + K; ++i) {
    sig[sigOffset + i] = 0;
  }

  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      if (h.vec[i].coeffs[j] !== 0) {
        sig[sigOffset + k++] = j;
      }
    }

    sig[sigOffset + OMEGA + i] = k;
  }
}

function unpackSig(cP, z, hP, sig) {
  let sigOffset = 0;
  const c = cP; // ctilde
  const h = hP;
  for (let i = 0; i < CTILDEBytes; ++i) {
    c[i] = sig[i];
  }
  sigOffset += CTILDEBytes;

  for (let i = 0; i < L; ++i) {
    polyZUnpack(z.vec[i], sig, sigOffset + i * PolyZPackedBytes);
  }
  sigOffset += L * PolyZPackedBytes;

  /* Decode h */
  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      h.vec[i].coeffs[j] = 0;
    }

    if (sig[sigOffset + OMEGA + i] < k || sig[sigOffset + OMEGA + i] > OMEGA) {
      return 1;
    }

    for (let j = k; j < sig[sigOffset + OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if (j > k && sig[sigOffset + j] <= sig[sigOffset + j - 1]) {
        return 1;
      }
      h.vec[i].coeffs[sig[sigOffset + j]] = 1;
    }

    k = sig[sigOffset + OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for (let j = k; j < OMEGA; ++j) {
    if (sig[sigOffset + j]) {
      return 1;
    }
  }

  return 0;
}

const MAX_BYTES = 65536;

function getWebCrypto() {
  if (typeof globalThis === 'object' && globalThis.crypto) return globalThis.crypto;
  return null;
}

function randomBytes(size) {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError('size must be a non-negative integer');
  }

  const cryptoObj = getWebCrypto();
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    const out = new Uint8Array(size);
    for (let i = 0; i < size; i += MAX_BYTES) {
      cryptoObj.getRandomValues(out.subarray(i, Math.min(size, i + MAX_BYTES)));
    }
    {
      let acc = 0;
      for (let i = 0; i < 16; i++) acc |= out[i];
      if (acc === 0) throw new Error('getRandomValues returned all zeros');
    }
    return out;
  }

  throw new Error('Secure random number generation is not supported by this environment');
}

/**
 * Security utilities for post-quantum signature schemes
 *
 * IMPORTANT: JavaScript cannot guarantee secure memory zeroization.
 * See SECURITY.md for details on limitations.
 */

/**
 * Attempts to zero out a Uint8Array buffer.
 *
 * WARNING: This is a BEST-EFFORT operation. Due to JavaScript/JIT limitations:
 * - The write may be optimized away if the buffer is unused afterward
 * - Copies may exist in garbage collector memory
 * - Data may have been swapped to disk
 *
 * For high-security applications, consider native implementations (go-qrllib)
 * or hardware security modules.
 *
 * @param {Uint8Array} buffer - The buffer to zero
 * @returns {void}
 */
function zeroize(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('zeroize requires a Uint8Array');
  }
  // Use fill(0) for zeroing - best effort
  buffer.fill(0);
  // Accumulator-OR over all bytes to discourage dead-store elimination
  // (Reading every byte makes it harder for JIT to prove fill is dead)
  let check = 0;
  for (let i = 0; i < buffer.length; i++) check |= buffer[i];
  if (check !== 0) {
    throw new Error('zeroize failed');
  }
}

/**
 * Checks if a buffer is all zeros.
 * Uses constant-time comparison to avoid timing leaks.
 *
 * @param {Uint8Array} buffer - The buffer to check
 * @returns {boolean} True if all bytes are zero
 */
function isZero(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('isZero requires a Uint8Array');
  }
  let acc = 0;
  for (let i = 0; i < buffer.length; i++) {
    acc |= buffer[i];
  }
  return acc === 0;
}

/**
 * Default signing context ("ZOND" in ASCII).
 * Used for domain separation per FIPS 204.
 * @constant {Uint8Array}
 */
const DEFAULT_CTX = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]); // "ZOND"

/**
 * Convert hex string to Uint8Array with strict validation.
 *
 * NOTE: This function accepts multiple hex formats (with/without 0x prefix,
 * leading/trailing whitespace). While user-friendly, this flexibility could
 * mask input errors. Applications requiring strict format validation should
 * validate hex format before calling cryptographic functions, e.g.:
 *   - Reject strings with 0x prefix if raw hex is expected
 *   - Reject strings with whitespace
 *   - Enforce consistent casing (lowercase/uppercase)
 *
 * @param {string} hex - Hex string (optional 0x prefix, even length).
 * @returns {Uint8Array} Decoded bytes.
 * @private
 */
function hexToBytes(hex) {
  /* c8 ignore start */
  if (typeof hex !== 'string') {
    throw new Error('message must be a hex string');
  }
  /* c8 ignore stop */
  let clean = hex.trim();
  // Accepts both "0x..." and raw hex formats for convenience
  if (clean.startsWith('0x') || clean.startsWith('0X')) {
    clean = clean.slice(2);
  }
  if (clean.length % 2 !== 0) {
    throw new Error('hex string must have an even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('hex string contains non-hex characters');
  }
  return hexToBytes$1(clean);
}

function messageToBytes(message) {
  if (typeof message === 'string') {
    return hexToBytes(message);
  }
  if (message instanceof Uint8Array) {
    return message;
  }
  throw new Error('message must be Uint8Array or hex string');
}

/**
 * Generate an ML-DSA-87 key pair.
 *
 * Key generation follows FIPS 204, using domain separator [K, L] during
 * seed expansion to ensure algorithm binding.
 *
 * @param {Uint8Array|null} passedSeed - Optional 32-byte seed for deterministic key generation.
 *   Pass null for random key generation.
 * @param {Uint8Array} pk - Output buffer for public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} sk - Output buffer for secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @returns {Uint8Array} The seed used for key generation (useful when passedSeed is null)
 * @throws {Error} If pk/sk buffers are null or wrong size, or if seed is wrong size
 *
 * @example
 * const pk = new Uint8Array(CryptoPublicKeyBytes);
 * const sk = new Uint8Array(CryptoSecretKeyBytes);
 * const seed = cryptoSignKeypair(null, pk, sk);
 */
function cryptoSignKeypair(passedSeed, pk, sk) {
  try {
    if (pk.length !== CryptoPublicKeyBytes) {
      throw new Error(`invalid pk length ${pk.length} | Expected length ${CryptoPublicKeyBytes}`);
    }
    if (sk.length !== CryptoSecretKeyBytes) {
      throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error(`pk/sk cannot be null`);
    } else {
      throw new Error(`${e.message}`);
    }
  }

  // Validate seed length if provided
  if (passedSeed !== null && passedSeed !== undefined) {
    if (passedSeed.length !== SeedBytes) {
      throw new Error(`invalid seed length ${passedSeed.length} | Expected length ${SeedBytes}`);
    }
  }

  const mat = new Array(K).fill().map(() => new PolyVecL());
  const s1 = new PolyVecL();
  const s2 = new PolyVecK();
  const t1 = new PolyVecK();
  const t0 = new PolyVecK();

  // Expand seed -> rho(32), rhoPrime(64), key(32) with domain sep [K, L]
  const seed = passedSeed || randomBytes(SeedBytes);

  const outputLength = 2 * SeedBytes + CRHBytes;
  const domainSep = new Uint8Array([K, L]);
  const seedBuf = shake256.create({}).update(seed).update(domainSep).xof(outputLength);
  const rho = seedBuf.slice(0, SeedBytes);
  const rhoPrime = seedBuf.slice(SeedBytes, SeedBytes + CRHBytes);
  const key = seedBuf.slice(SeedBytes + CRHBytes);

  let s1hat;
  try {
    // Expand matrix
    polyVecMatrixExpand(mat, rho);

    // Sample short vectors s1 and s2
    polyVecLUniformEta(s1, rhoPrime, 0);
    polyVecKUniformEta(s2, rhoPrime, L);

    // Matrix-vector multiplication
    s1hat = new PolyVecL();
    s1hat.copy(s1);
    polyVecLNTT(s1hat);
    polyVecMatrixPointWiseMontgomery(t1, mat, s1hat);
    polyVecKReduce(t1);
    polyVecKInvNTTToMont(t1);

    // Add error vector s2
    polyVecKAdd(t1, t1, s2);

    // Extract t1 and write public key
    polyVecKCAddQ(t1);
    polyVecKPower2round(t1, t0, t1);
    packPk(pk, rho, t1);

    // Compute tr = SHAKE256(pk) (64 bytes) and write secret key
    const tr = shake256.create({}).update(pk).xof(TRBytes);
    packSk(sk, rho, tr, key, t0, s1, s2);

    return seed;
  } finally {
    zeroize(seedBuf);
    zeroize(rhoPrime);
    zeroize(key);
    for (let i = 0; i < L; i++) s1.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) s2.vec[i].coeffs.fill(0);
    if (s1hat) for (let i = 0; i < L; i++) s1hat.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) t0.vec[i].coeffs.fill(0);
  }
}

/**
 * Create a detached signature for a message with optional context.
 *
 * Uses the ML-DSA-87 (FIPS 204) signing algorithm with rejection sampling.
 * The context parameter provides domain separation as required by FIPS 204.
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce for hedged signing.
 *   If false, use deterministic nonce derived from message and key.
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string for domain separation (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {number} 0 on success
 * @throws {Error} If sk is wrong size or context exceeds 255 bytes
 *
 * @example
 * const sig = new Uint8Array(CryptoBytes);
 * cryptoSignSignature(sig, message, sk, false);
 * // Or with custom context:
 * cryptoSignSignature(sig, message, sk, false, new Uint8Array([0x01, 0x02]));
 */
function cryptoSignSignature(sig, m, sk, randomizedSigning, ctx = DEFAULT_CTX) {
  if (!sig || sig.length < CryptoBytes) {
    throw new Error(`sig must be at least ${CryptoBytes} bytes`);
  }
  if (ctx.length > 255) throw new Error(`invalid context length: ${ctx.length} (max 255)`);
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const rho = new Uint8Array(SeedBytes);
  const tr = new Uint8Array(TRBytes);
  const key = new Uint8Array(SeedBytes);
  let rhoPrime = new Uint8Array(CRHBytes);
  let nonce = 0;
  const mat = Array(K)
    .fill()
    .map(() => new PolyVecL());
  const s1 = new PolyVecL();
  const y = new PolyVecL();
  const z = new PolyVecL();
  const t0 = new PolyVecK();
  const s2 = new PolyVecK();
  const w1 = new PolyVecK();
  const w0 = new PolyVecK();
  const h = new PolyVecK();
  const cp = new Poly();

  try {
    unpackSk(rho, tr, key, t0, s1, s2, sk);

    // pre = 0x00 || len(ctx) || ctx
    const pre = new Uint8Array(2 + ctx.length);
    pre[0] = 0;
    pre[1] = ctx.length;
    pre.set(ctx, 2);

    const mBytes = messageToBytes(m);

    // mu = SHAKE256(tr || pre || m)
    const mu = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);

    // rhoPrime = SHAKE256(key || rnd || mu)
    const rnd = randomizedSigning ? randomBytes(RNDBytes) : new Uint8Array(RNDBytes);
    rhoPrime = shake256.create({}).update(key).update(rnd).update(mu).xof(CRHBytes);

    polyVecMatrixExpand(mat, rho);
    polyVecLNTT(s1);
    polyVecKNTT(s2);
    polyVecKNTT(t0);

    while (true) {
      polyVecLUniformGamma1(y, rhoPrime, nonce++);
      // Matrix-vector multiplication
      z.copy(y);
      polyVecLNTT(z);
      polyVecMatrixPointWiseMontgomery(w1, mat, z);
      polyVecKReduce(w1);
      polyVecKInvNTTToMont(w1);

      // Decompose w and call the random oracle
      polyVecKCAddQ(w1);
      polyVecKDecompose(w1, w0, w1);
      polyVecKPackW1(sig, w1);

      // ctilde = SHAKE256(mu || w1_packed) (64 bytes)
      const ctilde = shake256
        .create({})
        .update(mu)
        .update(sig.slice(0, K * PolyW1PackedBytes))
        .xof(CTILDEBytes);

      polyChallenge(cp, ctilde);
      polyNTT(cp);

      // Compute z, reject if it reveals secret
      polyVecLPointWisePolyMontgomery(z, cp, s1);
      polyVecLInvNTTToMont(z);
      polyVecLAdd(z, z, y);
      polyVecLReduce(z);
      if (polyVecLChkNorm(z, GAMMA1 - BETA) !== 0) {
        continue;
      }

      polyVecKPointWisePolyMontgomery(h, cp, s2);
      polyVecKInvNTTToMont(h);
      polyVecKSub(w0, w0, h);
      polyVecKReduce(w0);
      if (polyVecKChkNorm(w0, GAMMA2 - BETA) !== 0) {
        continue;
      }

      polyVecKPointWisePolyMontgomery(h, cp, t0);
      polyVecKInvNTTToMont(h);
      polyVecKReduce(h);
      /* c8 ignore start */
      if (polyVecKChkNorm(h, GAMMA2) !== 0) {
        continue;
      }
      /* c8 ignore stop */

      polyVecKAdd(w0, w0, h);
      const n = polyVecKMakeHint(h, w0, w1);
      /* c8 ignore start */
      if (n > OMEGA) {
        continue;
      }
      /* c8 ignore stop */

      packSig(sig, ctilde, z, h);
      return 0;
    }
  } finally {
    zeroize(key);
    zeroize(rhoPrime);
    for (let i = 0; i < L; i++) s1.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) s2.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) t0.vec[i].coeffs.fill(0);
    for (let i = 0; i < L; i++) y.vec[i].coeffs.fill(0);
  }
}

/**
 * Sign a message, returning signature concatenated with message.
 *
 * This is the combined sign operation that produces a "signed message" containing
 * both the signature and the original message (signature || message).
 *
 * @param {string|Uint8Array} msg - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce; if false, deterministic
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string for domain separation (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {Uint8Array} Signed message (CryptoBytes + msg.length bytes)
 * @throws {Error} If signing fails
 *
 * @example
 * const signedMsg = cryptoSign(message, sk, false);
 * // signedMsg contains: signature (4627 bytes) || message
 */
function cryptoSign(msg, sk, randomizedSigning, ctx = DEFAULT_CTX) {
  const msgBytes = messageToBytes(msg);

  const sm = new Uint8Array(CryptoBytes + msgBytes.length);
  const mLen = msgBytes.length;
  for (let i = 0; i < mLen; ++i) {
    sm[CryptoBytes + mLen - 1 - i] = msgBytes[mLen - 1 - i];
  }
  const result = cryptoSignSignature(sm, msgBytes, sk, randomizedSigning, ctx);

  /* c8 ignore start */
  if (result !== 0) {
    throw new Error('failed to sign');
  }
  /* c8 ignore stop */
  return sm;
}

/**
 * Verify a detached signature with optional context.
 *
 * Performs constant-time verification to prevent timing side-channel attacks.
 * The context must match the one used during signing.
 *
 * @param {Uint8Array} sig - Signature to verify (must be CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message that was signed (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string used during signing (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {boolean} true if signature is valid, false otherwise
 *
 * @example
 * const isValid = cryptoSignVerify(signature, message, pk);
 * if (!isValid) {
 *   throw new Error('Invalid signature');
 * }
 */
function cryptoSignVerify(sig, m, pk, ctx = DEFAULT_CTX) {
  if (ctx.length > 255) return false;
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(CTILDEBytes);
  const c2 = new Uint8Array(CTILDEBytes);
  const cp = new Poly();
  const mat = new Array(K).fill().map(() => new PolyVecL());
  const z = new PolyVecL();
  const t1 = new PolyVecK();
  const w1 = new PolyVecK();
  const h = new PolyVecK();

  if (sig.length !== CryptoBytes) {
    return false;
  }
  if (pk.length !== CryptoPublicKeyBytes) {
    return false;
  }

  unpackPk(rho, t1, pk);
  if (unpackSig(c, z, h, sig)) {
    return false;
  }
  if (polyVecLChkNorm(z, GAMMA1 - BETA)) {
    return false;
  }

  /* Compute mu = SHAKE256(tr || pre || m) with tr = SHAKE256(pk) */
  const tr = shake256.create({}).update(pk).xof(TRBytes);

  const pre = new Uint8Array(2 + ctx.length);
  pre[0] = 0;
  pre[1] = ctx.length;
  pre.set(ctx, 2);

  let mBytes;
  try {
    mBytes = messageToBytes(m);
  } catch {
    return false;
  }
  const muFull = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);
  mu.set(muFull);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  polyChallenge(cp, c);
  polyVecMatrixExpand(mat, rho);

  polyVecLNTT(z);
  polyVecMatrixPointWiseMontgomery(w1, mat, z);

  polyNTT(cp);
  polyVecKShiftL(t1);
  polyVecKNTT(t1);
  polyVecKPointWisePolyMontgomery(t1, cp, t1);

  polyVecKSub(w1, w1, t1);
  polyVecKReduce(w1);
  polyVecKInvNTTToMont(w1);

  /* Reconstruct w1 */
  polyVecKCAddQ(w1);
  polyVecKUseHint(w1, w1, h);
  polyVecKPackW1(buf, w1);

  /* Call random oracle and verify challenge */
  const c2Hash = shake256.create({}).update(mu).update(buf).xof(CTILDEBytes);
  c2.set(c2Hash);

  // Constant-time comparison to prevent timing attacks
  let diff = 0;
  for (i = 0; i < CTILDEBytes; ++i) {
    diff |= c[i] ^ c2[i];
  }
  return diff === 0;
}

/**
 * Open a signed message (verify and extract message).
 *
 * This is the counterpart to cryptoSign(). It verifies the signature and
 * extracts the original message from a signed message.
 *
 * @param {Uint8Array} sm - Signed message (signature || message)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} [ctx=DEFAULT_CTX] - Context string used during signing (max 255 bytes).
 *   Defaults to "ZOND" for QRL compatibility.
 * @returns {Uint8Array|undefined} The original message if valid, undefined if verification fails
 *
 * @example
 * const message = cryptoSignOpen(signedMsg, pk);
 * if (message === undefined) {
 *   throw new Error('Invalid signature');
 * }
 */
function cryptoSignOpen(sm, pk, ctx = DEFAULT_CTX) {
  if (sm.length < CryptoBytes) {
    return undefined;
  }

  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk, ctx)) {
    return undefined;
  }

  return msg;
}

exports.BETA = BETA;
exports.CRHBytes = CRHBytes;
exports.CTILDEBytes = CTILDEBytes;
exports.CryptoBytes = CryptoBytes;
exports.CryptoPublicKeyBytes = CryptoPublicKeyBytes;
exports.CryptoSecretKeyBytes = CryptoSecretKeyBytes;
exports.D = D;
exports.ETA = ETA;
exports.GAMMA1 = GAMMA1;
exports.GAMMA2 = GAMMA2;
exports.K = K;
exports.KeccakState = KeccakState;
exports.L = L;
exports.N = N;
exports.OMEGA = OMEGA;
exports.Poly = Poly;
exports.PolyETAPackedBytes = PolyETAPackedBytes;
exports.PolyT0PackedBytes = PolyT0PackedBytes;
exports.PolyT1PackedBytes = PolyT1PackedBytes;
exports.PolyUniformETANBlocks = PolyUniformETANBlocks;
exports.PolyUniformGamma1NBlocks = PolyUniformGamma1NBlocks;
exports.PolyUniformNBlocks = PolyUniformNBlocks;
exports.PolyVecHPackedBytes = PolyVecHPackedBytes;
exports.PolyVecK = PolyVecK;
exports.PolyVecL = PolyVecL;
exports.PolyW1PackedBytes = PolyW1PackedBytes;
exports.PolyZPackedBytes = PolyZPackedBytes;
exports.Q = Q;
exports.QInv = QInv;
exports.RNDBytes = RNDBytes;
exports.SeedBytes = SeedBytes;
exports.Shake128Rate = Shake128Rate;
exports.Shake256Rate = Shake256Rate;
exports.Stream128BlockBytes = Stream128BlockBytes;
exports.Stream256BlockBytes = Stream256BlockBytes;
exports.TAU = TAU;
exports.TRBytes = TRBytes;
exports.cAddQ = cAddQ;
exports.cryptoSign = cryptoSign;
exports.cryptoSignKeypair = cryptoSignKeypair;
exports.cryptoSignOpen = cryptoSignOpen;
exports.cryptoSignSignature = cryptoSignSignature;
exports.cryptoSignVerify = cryptoSignVerify;
exports.decompose = decompose;
exports.invNTTToMont = invNTTToMont;
exports.isZero = isZero;
exports.makeHint = makeHint;
exports.mldsaShake128StreamInit = mldsaShake128StreamInit;
exports.mldsaShake256StreamInit = mldsaShake256StreamInit;
exports.montgomeryReduce = montgomeryReduce;
exports.ntt = ntt;
exports.packPk = packPk;
exports.packSig = packSig;
exports.packSk = packSk;
exports.polyAdd = polyAdd;
exports.polyCAddQ = polyCAddQ;
exports.polyChallenge = polyChallenge;
exports.polyChkNorm = polyChkNorm;
exports.polyDecompose = polyDecompose;
exports.polyEtaPack = polyEtaPack;
exports.polyEtaUnpack = polyEtaUnpack;
exports.polyInvNTTToMont = polyInvNTTToMont;
exports.polyMakeHint = polyMakeHint;
exports.polyNTT = polyNTT;
exports.polyPointWiseMontgomery = polyPointWiseMontgomery;
exports.polyPower2round = polyPower2round;
exports.polyReduce = polyReduce;
exports.polyShiftL = polyShiftL;
exports.polySub = polySub;
exports.polyT0Pack = polyT0Pack;
exports.polyT0Unpack = polyT0Unpack;
exports.polyT1Pack = polyT1Pack;
exports.polyT1Unpack = polyT1Unpack;
exports.polyUniform = polyUniform;
exports.polyUniformEta = polyUniformEta;
exports.polyUniformGamma1 = polyUniformGamma1;
exports.polyUseHint = polyUseHint;
exports.polyVecKAdd = polyVecKAdd;
exports.polyVecKCAddQ = polyVecKCAddQ;
exports.polyVecKChkNorm = polyVecKChkNorm;
exports.polyVecKDecompose = polyVecKDecompose;
exports.polyVecKInvNTTToMont = polyVecKInvNTTToMont;
exports.polyVecKMakeHint = polyVecKMakeHint;
exports.polyVecKNTT = polyVecKNTT;
exports.polyVecKPackW1 = polyVecKPackW1;
exports.polyVecKPointWisePolyMontgomery = polyVecKPointWisePolyMontgomery;
exports.polyVecKPower2round = polyVecKPower2round;
exports.polyVecKReduce = polyVecKReduce;
exports.polyVecKShiftL = polyVecKShiftL;
exports.polyVecKSub = polyVecKSub;
exports.polyVecKUniformEta = polyVecKUniformEta;
exports.polyVecKUseHint = polyVecKUseHint;
exports.polyVecLAdd = polyVecLAdd;
exports.polyVecLChkNorm = polyVecLChkNorm;
exports.polyVecLInvNTTToMont = polyVecLInvNTTToMont;
exports.polyVecLNTT = polyVecLNTT;
exports.polyVecLPointWiseAccMontgomery = polyVecLPointWiseAccMontgomery;
exports.polyVecLPointWisePolyMontgomery = polyVecLPointWisePolyMontgomery;
exports.polyVecLReduce = polyVecLReduce;
exports.polyVecLUniformEta = polyVecLUniformEta;
exports.polyVecLUniformGamma1 = polyVecLUniformGamma1;
exports.polyVecMatrixExpand = polyVecMatrixExpand;
exports.polyVecMatrixPointWiseMontgomery = polyVecMatrixPointWiseMontgomery;
exports.polyW1Pack = polyW1Pack;
exports.polyZPack = polyZPack;
exports.polyZUnpack = polyZUnpack;
exports.power2round = power2round;
exports.reduce32 = reduce32;
exports.rejEta = rejEta;
exports.rejUniform = rejUniform;
exports.shake128Absorb = shake128Absorb;
exports.shake128Finalize = shake128Finalize;
exports.shake128Init = shake128Init;
exports.shake128SqueezeBlocks = shake128SqueezeBlocks;
exports.shake256Absorb = shake256Absorb;
exports.shake256Finalize = shake256Finalize;
exports.shake256Init = shake256Init;
exports.shake256SqueezeBlocks = shake256SqueezeBlocks;
exports.unpackPk = unpackPk;
exports.unpackSig = unpackSig;
exports.unpackSk = unpackSk;
exports.useHint = useHint;
exports.zeroize = zeroize;
exports.zetas = zetas;
