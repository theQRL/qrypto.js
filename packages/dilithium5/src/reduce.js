import {Q, QInv} from "./const.js";

export function montgomeryReduce(a) {
    let t = BigInt.asIntN(32, BigInt.asIntN(64, BigInt.asIntN(32, a)) * BigInt(QInv));
    t = BigInt.asIntN(32, (a - (t * BigInt(Q))) >> 32n);
    return t;
}

export function reduce32(a) {
    let t = (a + (1 << 22)) >> 23;
    t = a -  (t * Q)
    return t;
}

export function cAddQ(a) {
    a += (a >> 31) & Q;
    return a;
}
