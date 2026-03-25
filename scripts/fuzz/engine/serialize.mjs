import fs from 'node:fs';

const HEX = '0123456789abcdef';

export function toHex(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0x0F];
  }
  return out;
}

export function fromHex(str) {
  const clean = str.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new RangeError('Hex string must have even length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexVal(clean.charCodeAt(i * 2));
    const lo = hexVal(clean.charCodeAt(i * 2 + 1));
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexVal(charCode) {
  if (charCode >= 48 && charCode <= 57) return charCode - 48;       // 0-9
  if (charCode >= 65 && charCode <= 70) return charCode - 55;       // A-F
  if (charCode >= 97 && charCode <= 102) return charCode - 87;      // a-f
  throw new RangeError(`Invalid hex character: ${String.fromCharCode(charCode)}`);
}

export function writeJSON(filePath, obj) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

export function readJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}
