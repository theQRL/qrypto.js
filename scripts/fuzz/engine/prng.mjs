export class PRNG {
  constructor(seed) {
    seed = seed | 0;
    this.s = new Int32Array([
      seed,
      seed ^ 0x6D2B79F5,
      seed ^ 0xBEEF,
      seed ^ 0xDEAD,
    ]);
  }

  nextUint32() {
    const s = this.s;
    const result = Math.imul(s[1], 5);
    const t = s[1] << 9;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = (s[3] << 11) | (s[3] >>> 21);
    return result >>> 0;
  }

  nextFloat() {
    return this.nextUint32() / 0x100000000;
  }

  nextRange(min, max) {
    return min + (this.nextUint32() % (max - min));
  }

  nextBytes(n) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 4) {
      const v = this.nextUint32();
      out[i] = v & 0xFF;
      if (i + 1 < n) out[i + 1] = (v >>> 8) & 0xFF;
      if (i + 2 < n) out[i + 2] = (v >>> 16) & 0xFF;
      if (i + 3 < n) out[i + 3] = (v >>> 24) & 0xFF;
    }
    return out;
  }

  shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = this.nextUint32() % (i + 1);
      const tmp = arr[i];
      arr[i] = arr[j];
      arr[j] = tmp;
    }
    return arr;
  }

  pick(arr) {
    return arr[this.nextUint32() % arr.length];
  }
}
