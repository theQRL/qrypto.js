export function load64(x, xOffset) {
  let r = BigInt(0);

  for (let i = 0; i < 8; i++) r = BigInt.asUintN(64, r | BigInt.asUintN(64, BigInt(x[xOffset + i]) << BigInt(8 * i)));

  return r;
}

export function store64(xP, xOffset, u) {
  const x = xP;
  for (let i = 0; i < 8; i++) x[xOffset + i] = Number((u >> BigInt(8 * i)) & 0xffn);
}