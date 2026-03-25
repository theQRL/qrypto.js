import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { toHex, writeJSON } from './serialize.mjs';

export function loadCorpus(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.bin'))
    .sort()
    .map(f => new Uint8Array(fs.readFileSync(path.join(dir, f))));
}

export function saveCase(dir, entry) {
  fs.mkdirSync(dir, { recursive: true });

  const ts = Date.now();
  const tag = crypto.randomBytes(4).toString('hex');
  const basename = `${ts}-${tag}`;

  const meta = {
    seed: entry.seed,
    parent: entry.parent ?? null,
    family: entry.family ?? null,
    harness: entry.harness ?? null,
    result: typeof entry.result === 'string' ? entry.result : String(entry.result),
    inputLen: entry.input ? entry.input.length : 0,
    inputHex: entry.input ? toHex(entry.input.subarray(0, 64)) : null,
    timestamp: new Date().toISOString(),
  };

  writeJSON(path.join(dir, `${basename}.json`), meta);

  if (entry.input) {
    fs.writeFileSync(path.join(dir, `${basename}.bin`), entry.input);
  }

  return basename;
}

const DEFAULT_CORPUS_SIZE = 24;

export function buildBaseCorpus(keygen, sign, constants, count = DEFAULT_CORPUS_SIZE) {
  const corpus = [];

  for (let i = 0; i < count; i++) {
    const seed = 0x10000 + i * 7919;

    const keys = keygen();
    const pk = keys.pk ?? keys.publicKey;
    const sk = keys.sk ?? keys.secretKey ?? keys.privateKey;

    const msgLen = 32 + (i % 64);
    const msg = new Uint8Array(msgLen);
    for (let j = 0; j < msgLen; j++) {
      msg[j] = ((seed + j * 31) ^ (j * j)) & 0xFF;
    }

    const ctx = new Uint8Array(0);

    let sig;
    try {
      sig = sign(msg, sk, ctx);
    } catch {
      sig = sign(msg, sk);
    }

    corpus.push({
      pk: new Uint8Array(pk),
      sk: new Uint8Array(sk),
      sig: new Uint8Array(sig),
      msg: new Uint8Array(msg),
      ctx,
      seed,
    });
  }

  return corpus;
}
