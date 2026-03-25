/**
 * Byte-level mutation engine for fuzz testing.
 *
 * Mutation families and their approximate weights:
 *   35% bit flips          | 20% truncation/extension | 15% region fill
 *   10% region copy        | 10% hint-region mutation | 5%  donor splice
 *   5%  full random region
 */

function clampLen(len, minLen, maxLen) {
  if (minLen !== undefined && len < minLen) len = minLen;
  if (maxLen !== undefined && len > maxLen) len = maxLen;
  return Math.max(0, len);
}

function bitFlips(buf, prng) {
  const out = new Uint8Array(buf);
  const count = prng.nextRange(1, 9);
  for (let i = 0; i < count; i++) {
    const pos = prng.nextUint32() % out.length;
    const bit = prng.nextUint32() % 8;
    out[pos] ^= 1 << bit;
  }
  return out;
}

function truncateOrExtend(buf, prng, minLen, maxLen) {
  const delta = prng.nextRange(-16, 17);
  let newLen = clampLen(buf.length + delta, minLen, maxLen);
  if (newLen === buf.length && newLen > 1) newLen--;
  const out = new Uint8Array(newLen);
  out.set(buf.subarray(0, Math.min(buf.length, newLen)));
  if (newLen > buf.length) {
    for (let i = buf.length; i < newLen; i++) {
      out[i] = prng.nextUint32() & 0xFF;
    }
  }
  return out;
}

function regionFill(buf, prng) {
  const out = new Uint8Array(buf);
  const regionLen = prng.nextRange(1, Math.max(2, out.length >>> 2));
  const start = prng.nextUint32() % Math.max(1, out.length - regionLen);
  const kind = prng.nextUint32() % 3;
  const fillByte = kind === 0 ? 0x00 : kind === 1 ? 0xFF : (prng.nextUint32() & 0xFF);
  for (let i = start; i < start + regionLen && i < out.length; i++) {
    out[i] = fillByte;
  }
  return out;
}

function regionCopy(buf, prng) {
  const out = new Uint8Array(buf);
  if (out.length < 4) return bitFlips(buf, prng);
  const regionLen = prng.nextRange(1, Math.max(2, out.length >>> 3));
  const src = prng.nextUint32() % Math.max(1, out.length - regionLen);
  let dst = prng.nextUint32() % Math.max(1, out.length - regionLen);
  if (dst === src) dst = (dst + regionLen) % Math.max(1, out.length - regionLen);
  for (let i = 0; i < regionLen && dst + i < out.length; i++) {
    out[dst + i] = out[src + i];
  }
  return out;
}

function hintRegion(buf, prng, hintOffset, hintLen) {
  const out = new Uint8Array(buf);
  const offset = hintOffset ?? prng.nextUint32() % out.length;
  const len = hintLen ?? prng.nextRange(1, Math.max(2, 16));
  for (let i = offset; i < offset + len && i < out.length; i++) {
    out[i] = prng.nextUint32() & 0xFF;
  }
  return out;
}

function donorSplice(buf, prng, donor) {
  if (!donor || donor.length === 0) return bitFlips(buf, prng);
  const out = new Uint8Array(buf);
  const spliceLen = prng.nextRange(1, Math.max(2, Math.min(donor.length, out.length) >>> 2));
  const donorStart = prng.nextUint32() % Math.max(1, donor.length - spliceLen);
  const dstStart = prng.nextUint32() % Math.max(1, out.length - spliceLen);
  for (let i = 0; i < spliceLen && dstStart + i < out.length; i++) {
    out[dstStart + i] = donor[donorStart + i];
  }
  return out;
}

function randomCorrupt(buf, prng) {
  const out = new Uint8Array(buf);
  const regionLen = prng.nextRange(1, Math.max(2, out.length >>> 2));
  const start = prng.nextUint32() % Math.max(1, out.length - regionLen);
  for (let i = start; i < start + regionLen && i < out.length; i++) {
    out[i] = prng.nextUint32() & 0xFF;
  }
  return out;
}

const FAMILIES = [
  { weight: 35, name: 'bitFlip' },
  { weight: 20, name: 'truncExt' },
  { weight: 15, name: 'regionFill' },
  { weight: 10, name: 'regionCopy' },
  { weight: 10, name: 'hintRegion' },
  { weight: 5,  name: 'donorSplice' },
  { weight: 5,  name: 'randomCorrupt' },
];

const TOTAL_WEIGHT = FAMILIES.reduce((s, f) => s + f.weight, 0);

function pickFamily(prng) {
  let r = prng.nextUint32() % TOTAL_WEIGHT;
  for (const f of FAMILIES) {
    if (r < f.weight) return f.name;
    r -= f.weight;
  }
  return 'bitFlip';
}

export function mutate(buf, prng, opts = {}) {
  const { donor, hintOffset, hintLen, minLen, maxLen } = opts;
  if (!(buf instanceof Uint8Array) || buf.length === 0) {
    return prng.nextBytes(prng.nextRange(1, 64));
  }

  const family = pickFamily(prng);
  let result;

  switch (family) {
    case 'bitFlip':
      result = bitFlips(buf, prng);
      break;
    case 'truncExt':
      result = truncateOrExtend(buf, prng, minLen, maxLen);
      break;
    case 'regionFill':
      result = regionFill(buf, prng);
      break;
    case 'regionCopy':
      result = regionCopy(buf, prng);
      break;
    case 'hintRegion':
      result = hintRegion(buf, prng, hintOffset, hintLen);
      break;
    case 'donorSplice':
      result = donorSplice(buf, prng, donor);
      break;
    case 'randomCorrupt':
      result = randomCorrupt(buf, prng);
      break;
    default:
      result = bitFlips(buf, prng);
  }

  return result;
}

export { pickFamily, FAMILIES };
