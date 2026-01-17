const HEX_RE = /^[0-9a-fA-F]*$/;

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  if (!HEX_RE.test(clean)) {
    throw new Error('Invalid hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

function stringToBytes(str, encoding) {
  const enc = (encoding || 'utf8').toLowerCase();
  if (enc === 'hex') {
    return hexToBytes(str);
  }
  if (enc === 'binary' || enc === 'latin1') {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i += 1) {
      out[i] = str.charCodeAt(i) & 0xff;
    }
    return out;
  }
  return new TextEncoder().encode(str);
}

class BufferPolyfill extends Uint8Array {
  static from(input, encoding) {
    if (typeof input === 'string') {
      return new BufferPolyfill(stringToBytes(input, encoding));
    }
    if (input instanceof ArrayBuffer) {
      return new BufferPolyfill(new Uint8Array(input));
    }
    if (ArrayBuffer.isView(input)) {
      const view = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      return new BufferPolyfill(view);
    }
    if (Array.isArray(input)) {
      return new BufferPolyfill(Uint8Array.from(input));
    }
    throw new TypeError('Unsupported Buffer input');
  }

  static alloc(size, fill = 0) {
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new RangeError('The "size" argument must be a non-negative integer');
    }
    const buf = new BufferPolyfill(size);
    buf.fill(typeof fill === 'number' ? fill & 0xff : 0);
    return buf;
  }

  toString(encoding) {
    const enc = (encoding || 'utf8').toLowerCase();
    if (enc === 'hex') {
      return bytesToHex(this);
    }
    if (enc === 'binary' || enc === 'latin1') {
      let out = '';
      for (const b of this) {
        out += String.fromCharCode(b);
      }
      return out;
    }
    return bytesToUtf8(this);
  }
}

BufferPolyfill.isBuffer = (value) => value instanceof BufferPolyfill;

export function installBuffer() {
  if (!globalThis.Buffer) {
    globalThis.Buffer = BufferPolyfill;
  }
}
