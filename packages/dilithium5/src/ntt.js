import {N, zetas} from "./const.js";
import {montgomeryReduce} from "./reduce.js";

export function ntt(a) {
    let k = 0;
    let j = 0;

    for (let len = 128; len > 0; len >>= 1) {
        for (let start = 0; start < N; start = j + len) {
            let zeta = zetas[++k];
            for (j = start; j < start + len; ++j) {
                let t = Number(montgomeryReduce(BigInt.asIntN(64, BigInt(zeta) * BigInt(a[j + len]))));
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

export function invNTTToMont(a) {
    const f = 41978n; // mont^2/256
    let j = 0;
    let k = 256;

    for (let len = 1; len < N; len <<= 1) {
        for (let start = 0; start < N; start = j + len) {
            let zeta = BigInt.asIntN(32, BigInt(-zetas[--k]));
            for (j = start; j < start + len; ++j) {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = Number(montgomeryReduce(BigInt.asIntN(64,zeta * BigInt(a[j + len]))));
            }
        }
    }

    for (let j = 0; j < N; ++j) {
        a[j] = Number(montgomeryReduce(BigInt.asIntN(64,f * BigInt(a[j]))));
    }
}
