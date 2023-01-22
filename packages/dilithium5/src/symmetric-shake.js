import {
    shake128Absorb,
    shake128Finalize,
    shake128Init,
    shake256Absorb,
    shake256Finalize,
    shake256Init
} from "./fips202.js";
import {CRHBytes, SeedBytes} from "./const.js";


export function dilithiumShake128StreamInit(state, seed, nonce)
{
    if (seed.length !== SeedBytes ) {
        throw new Error(`invalid seed length ${seed.length} | expected ${SeedBytes}`)
    }
    let t = new Uint8Array(2);
    t[0] = nonce & 0xff;
    t[1] = nonce >> 8;

    shake128Init(state);
    shake128Absorb(state, seed);
    shake128Absorb(state, t);
    shake128Finalize(state);
}

export function dilithiumShake256StreamInit(state, seed, nonce) {
    if (seed.length !== CRHBytes ) {
        throw new Error(`invalid seed length ${seed.length} | expected ${CRHBytes}`)
    }
    let t = new Uint8Array(2);
    t[0] = nonce & 0xff;
    t[1] = nonce >> 8;

    shake256Init(state);
    shake256Absorb(state, seed);
    shake256Absorb(state, t);
    shake256Finalize(state);
}
