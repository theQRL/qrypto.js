/**
 * @param {String} out
 * @param {Uint8Array} msg
 */
export function SHAKE256(out, msg) {
  hasher = sha3.NewShake256();
  hasher.Write(msg);
  hasher.Read(out);
  return out;
}
