import { Shake128Rate, Shake256Rate } from './const.js';

export const NRounds = 24;

export const KeccakFRoundConstants = BigUint64Array.from([
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
]);

export class KeccakState {
  constructor() {
    this.s = new BigUint64Array(25);
    this.pos = 0;
  }
}

export function ROL(a, offset) {
  return BigInt.asUintN(64, BigInt.asUintN(64, a << offset) ^ (a >> (64n - offset)));
}

export function load64(x, xOffset) {
  let r = BigInt(0);

  for (let i = 0; i < 8; i++) r = BigInt.asUintN(64, r | BigInt.asUintN(64, BigInt(x[xOffset + i]) << BigInt(8 * i)));

  return r;
}

export function store64(xP, xOffset, u) {
  const x = xP;
  for (let i = 0; i < 8; i++) x[xOffset + i] = Number((u >> BigInt(8 * i)) & 0xffn);
}

export function KeccakF1600StatePermute(stateP) {
  const state = stateP;
  // copyFromState(A, state)
  let Aba = state[0];
  let Abe = state[1];
  let Abi = state[2];
  let Abo = state[3];
  let Abu = state[4];
  let Aga = state[5];
  let Age = state[6];
  let Agi = state[7];
  let Ago = state[8];
  let Agu = state[9];
  let Aka = state[10];
  let Ake = state[11];
  let Aki = state[12];
  let Ako = state[13];
  let Aku = state[14];
  let Ama = state[15];
  let Ame = state[16];
  let Ami = state[17];
  let Amo = state[18];
  let Amu = state[19];
  let Asa = state[20];
  let Ase = state[21];
  let Asi = state[22];
  let Aso = state[23];
  let Asu = state[24];

  for (let round = 0; round < NRounds; round += 2) {
    //    prepareTheta
    let BCa = BigInt.asUintN(64, Aba ^ Aga ^ Aka ^ Ama ^ Asa);
    let BCe = BigInt.asUintN(64, Abe ^ Age ^ Ake ^ Ame ^ Ase);
    let BCi = BigInt.asUintN(64, Abi ^ Agi ^ Aki ^ Ami ^ Asi);
    let BCo = BigInt.asUintN(64, Abo ^ Ago ^ Ako ^ Amo ^ Aso);
    let BCu = BigInt.asUintN(64, Abu ^ Agu ^ Aku ^ Amu ^ Asu);

    // thetaRhoPiChiIotaPrepareTheta(round, A, E)
    let Da = BigInt.asUintN(64, BCu ^ ROL(BCe, 1n));
    let De = BigInt.asUintN(64, BCa ^ ROL(BCi, 1n));
    let Di = BigInt.asUintN(64, BCe ^ ROL(BCo, 1n));
    let Do = BigInt.asUintN(64, BCi ^ ROL(BCu, 1n));
    let Du = BigInt.asUintN(64, BCo ^ ROL(BCa, 1n));

    Aba = BigInt.asUintN(64, Aba ^ Da);
    BCa = Aba;
    Age = BigInt.asUintN(64, Age ^ De);
    BCe = ROL(Age, 44n);
    Aki = BigInt.asUintN(64, Aki ^ Di);
    BCi = ROL(Aki, 43n);
    Amo = BigInt.asUintN(64, Amo ^ Do);
    BCo = ROL(Amo, 21n);
    Asu = BigInt.asUintN(64, Asu ^ Du);
    BCu = ROL(Asu, 14n);
    let Eba = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    Eba = BigInt.asUintN(64, Eba ^ KeccakFRoundConstants[round]);
    let Ebe = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    let Ebi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    let Ebo = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    let Ebu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Abo = BigInt.asUintN(64, Abo ^ Do);
    BCa = ROL(Abo, 28n);
    Agu = BigInt.asUintN(64, Agu ^ Du);
    BCe = ROL(Agu, 20n);
    Aka = BigInt.asUintN(64, Aka ^ Da);
    BCi = ROL(Aka, 3n);
    Ame = BigInt.asUintN(64, Ame ^ De);
    BCo = ROL(Ame, 45n);
    Asi = BigInt.asUintN(64, Asi ^ Di);
    BCu = ROL(Asi, 61n);
    let Ega = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    let Ege = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    let Egi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    let Ego = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    let Egu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Abe = BigInt.asUintN(64, Abe ^ De);
    BCa = ROL(Abe, 1n);
    Agi = BigInt.asUintN(64, Agi ^ Di);
    BCe = ROL(Agi, 6n);
    Ako = BigInt.asUintN(64, Ako ^ Do);
    BCi = ROL(Ako, 25n);
    Amu = BigInt.asUintN(64, Amu ^ Du);
    BCo = ROL(Amu, 8n);
    Asa = BigInt.asUintN(64, Asa ^ Da);
    BCu = ROL(Asa, 18n);
    let Eka = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    let Eke = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    let Eki = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    let Eko = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    let Eku = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Abu = BigInt.asUintN(64, Abu ^ Du);
    BCa = ROL(Abu, 27n);
    Aga = BigInt.asUintN(64, Aga ^ Da);
    BCe = ROL(Aga, 36n);
    Ake = BigInt.asUintN(64, Ake ^ De);
    BCi = ROL(Ake, 10n);
    Ami = BigInt.asUintN(64, Ami ^ Di);
    BCo = ROL(Ami, 15n);
    Aso = BigInt.asUintN(64, Aso ^ Do);
    BCu = ROL(Aso, 56n);
    let Ema = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    let Eme = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    let Emi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    let Emo = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    let Emu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Abi = BigInt.asUintN(64, Abi ^ Di);
    BCa = ROL(Abi, 62n);
    Ago = BigInt.asUintN(64, Ago ^ Do);
    BCe = ROL(Ago, 55n);
    Aku = BigInt.asUintN(64, Aku ^ Du);
    BCi = ROL(Aku, 39n);
    Ama = BigInt.asUintN(64, Ama ^ Da);
    BCo = ROL(Ama, 41n);
    Ase = BigInt.asUintN(64, Ase ^ De);
    BCu = ROL(Ase, 2n);
    let Esa = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    let Ese = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    let Esi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    let Eso = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    let Esu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    //    prepareTheta
    BCa = BigInt.asUintN(64, Eba ^ Ega ^ Eka ^ Ema ^ Esa);
    BCe = BigInt.asUintN(64, Ebe ^ Ege ^ Eke ^ Eme ^ Ese);
    BCi = BigInt.asUintN(64, Ebi ^ Egi ^ Eki ^ Emi ^ Esi);
    BCo = BigInt.asUintN(64, Ebo ^ Ego ^ Eko ^ Emo ^ Eso);
    BCu = BigInt.asUintN(64, Ebu ^ Egu ^ Eku ^ Emu ^ Esu);

    // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
    Da = BigInt.asUintN(64, BCu ^ ROL(BCe, 1n));
    De = BigInt.asUintN(64, BCa ^ ROL(BCi, 1n));
    Di = BigInt.asUintN(64, BCe ^ ROL(BCo, 1n));
    Do = BigInt.asUintN(64, BCi ^ ROL(BCu, 1n));
    Du = BigInt.asUintN(64, BCo ^ ROL(BCa, 1n));

    Eba = BigInt.asUintN(64, Eba ^ Da);
    BCa = Eba;
    Ege = BigInt.asUintN(64, Ege ^ De);
    BCe = ROL(Ege, 44n);
    Eki = BigInt.asUintN(64, Eki ^ Di);
    BCi = ROL(Eki, 43n);
    Emo = BigInt.asUintN(64, Emo ^ Do);
    BCo = ROL(Emo, 21n);
    Esu = BigInt.asUintN(64, Esu ^ Du);
    BCu = ROL(Esu, 14n);
    Aba = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    Aba = BigInt.asUintN(64, Aba ^ KeccakFRoundConstants[round + 1]);
    Abe = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    Abi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    Abo = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    Abu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Ebo = BigInt.asUintN(64, Ebo ^ Do);
    BCa = ROL(Ebo, 28n);
    Egu = BigInt.asUintN(64, Egu ^ Du);
    BCe = ROL(Egu, 20n);
    Eka = BigInt.asUintN(64, Eka ^ Da);
    BCi = ROL(Eka, 3n);
    Eme = BigInt.asUintN(64, Eme ^ De);
    BCo = ROL(Eme, 45n);
    Esi = BigInt.asUintN(64, Esi ^ Di);
    BCu = ROL(Esi, 61n);
    Aga = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    Age = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    Agi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    Ago = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    Agu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Ebe = BigInt.asUintN(64, Ebe ^ De);
    BCa = ROL(Ebe, 1n);
    Egi = BigInt.asUintN(64, Egi ^ Di);
    BCe = ROL(Egi, 6n);
    Eko = BigInt.asUintN(64, Eko ^ Do);
    BCi = ROL(Eko, 25n);
    Emu = BigInt.asUintN(64, Emu ^ Du);
    BCo = ROL(Emu, 8n);
    Esa = BigInt.asUintN(64, Esa ^ Da);
    BCu = ROL(Esa, 18n);
    Aka = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    Ake = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    Aki = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    Ako = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    Aku = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Ebu = BigInt.asUintN(64, Ebu ^ Du);
    BCa = ROL(Ebu, 27n);
    Ega = BigInt.asUintN(64, Ega ^ Da);
    BCe = ROL(Ega, 36n);
    Eke = BigInt.asUintN(64, Eke ^ De);
    BCi = ROL(Eke, 10n);
    Emi = BigInt.asUintN(64, Emi ^ Di);
    BCo = ROL(Emi, 15n);
    Eso = BigInt.asUintN(64, Eso ^ Do);
    BCu = ROL(Eso, 56n);
    Ama = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    Ame = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    Ami = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    Amo = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    Amu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));

    Ebi = BigInt.asUintN(64, Ebi ^ Di);
    BCa = ROL(Ebi, 62n);
    Ego = BigInt.asUintN(64, Ego ^ Do);
    BCe = ROL(Ego, 55n);
    Eku = BigInt.asUintN(64, Eku ^ Du);
    BCi = ROL(Eku, 39n);
    Ema = BigInt.asUintN(64, Ema ^ Da);
    BCo = ROL(Ema, 41n);
    Ese = BigInt.asUintN(64, Ese ^ De);
    BCu = ROL(Ese, 2n);
    Asa = BigInt.asUintN(64, BCa ^ (~BCe & BCi));
    Ase = BigInt.asUintN(64, BCe ^ (~BCi & BCo));
    Asi = BigInt.asUintN(64, BCi ^ (~BCo & BCu));
    Aso = BigInt.asUintN(64, BCo ^ (~BCu & BCa));
    Asu = BigInt.asUintN(64, BCu ^ (~BCa & BCe));
  }

  state[0] = Aba;
  state[1] = Abe;
  state[2] = Abi;
  state[3] = Abo;
  state[4] = Abu;
  state[5] = Aga;
  state[6] = Age;
  state[7] = Agi;
  state[8] = Ago;
  state[9] = Agu;
  state[10] = Aka;
  state[11] = Ake;
  state[12] = Aki;
  state[13] = Ako;
  state[14] = Aku;
  state[15] = Ama;
  state[16] = Ame;
  state[17] = Ami;
  state[18] = Amo;
  state[19] = Amu;
  state[20] = Asa;
  state[21] = Ase;
  state[22] = Asi;
  state[23] = Aso;
  state[24] = Asu;
}

export function keccakInit(sP) {
  const s = sP;
  for (let i = 0; i < 25; i++) s[i] = 0n;
}

export function keccakAbsorb(sP, posP, r, input) {
  const s = sP;
  let pos = posP;
  let inLen = input.length;
  let i;
  let inputOffset = 0;
  while (pos + inLen >= r) {
    for (i = pos; i < r; i++)
      s[Math.floor(i / 8)] = BigInt.asUintN(
        64,
        s[Math.floor(i / 8)] ^ (BigInt(input[inputOffset++]) << BigInt(8 * (i % 8)))
      );
    inLen -= r - pos;
    KeccakF1600StatePermute(s);
    pos = 0;
  }

  for (i = pos; i < pos + inLen; i++) {
    s[Math.floor(i / 8)] = BigInt.asUintN(
      64,
      s[Math.floor(i / 8)] ^ (BigInt(input[inputOffset++]) << BigInt(8 * (i % 8)))
    );
  }

  return i;
}

export function keccakFinalize(sP, pos, r, p) {
  const s = sP;
  s[Math.floor(pos / 8)] = BigInt.asUintN(64, s[Math.floor(pos / 8)] ^ (BigInt(p) << BigInt(8 * (pos % 8))));
  s[Math.floor(r / 8) - 1] = BigInt.asUintN(64, s[Math.floor(r / 8) - 1] ^ (1n << 63n));
}

export function keccakSqueeze(outP, s, posP, r) {
  let pos = posP;
  const out = outP;
  let outLen = out.length;
  let outputOffset = 0;
  let i = 0;

  while (outLen) {
    if (pos === r) {
      KeccakF1600StatePermute(s);
      pos = 0;
    }
    for (i = pos; i < r && i < pos + outLen; i++) out[outputOffset++] = s[Math.floor(i / 8)] >> BigInt(8 * (i % 8));
    outLen -= i - pos;
    pos = i;
  }

  return pos;
}

export function keccakAbsorbOnce(sP, r, input, p) {
  const s = sP;
  let inLen = input.length;
  let inputOffset = 0;
  let i;

  for (i = 0; i < 25; i++) s[i] = 0;

  while (inLen >= r) {
    for (i = 0; i < Math.floor(r / 8); i++) s[i] = BigInt.asUintN(64, s[i] ^ load64(input, inputOffset + 8 * i));
    inputOffset += r;
    inLen -= r;
    KeccakF1600StatePermute(s);
  }

  for (i = 0; i < inLen; i++)
    s[Math.floor(i / 8)] = BigInt.asUintN(
      64,
      s[Math.floor(i / 8)] ^ (BigInt(input[inputOffset + i]) << BigInt(8 * (i % 8)))
    );

  s[Math.floor(i / 8)] = BigInt.asUintN(64, s[Math.floor(i / 8)] ^ (BigInt(p) << BigInt(8 * (i % 8))));
  s[Math.floor((r - 1) / 8)] = BigInt.asUintN(64, s[Math.floor((r - 1) / 8)] ^ (1n << 63n));
}

export function keccakSqueezeBlocks(output, outputOffsetP, nBlocksP, s, r) {
  let nBlocks = nBlocksP;
  let outputOffset = outputOffsetP;
  while (nBlocks) {
    KeccakF1600StatePermute(s);
    for (let i = 0; i < Math.floor(r / 8); i++) store64(output, outputOffset + 8 * i, s[i]);
    outputOffset += r;
    nBlocks -= 1;
  }
}

export function shake128Init(stateP) {
  const state = stateP;
  keccakInit(state.s);
  state.pos = 0;
}

export function shake128Absorb(stateP, input) {
  const state = stateP;
  state.pos = keccakAbsorb(state.s, state.pos, Shake128Rate, input);
}

export function shake128Finalize(stateP) {
  const state = stateP;
  keccakFinalize(state.s, state.pos, Shake128Rate, 0x1f);
  state.pos = Shake128Rate;
}

export function shake128Squeeze(out, stateP) {
  const state = stateP;
  state.pos = keccakSqueeze(out, state.s, state.pos, Shake128Rate);
}

export function shake128AbsorbOnce(stateP, input) {
  const state = stateP;
  keccakAbsorbOnce(state.s, Shake128Rate, input, 0x1f);
  state.pos = Shake128Rate;
}

export function shake128SqueezeBlocks(out, outputOffset, nBlocks, state) {
  keccakSqueezeBlocks(out, outputOffset, nBlocks, state.s, Shake128Rate);
}

export function shake256Init(stateP) {
  const state = stateP;
  keccakInit(state.s);
  state.pos = 0;
}

export function shake256Absorb(stateP, input) {
  const state = stateP;
  state.pos = keccakAbsorb(state.s, state.pos, Shake256Rate, input);
}

export function shake256Finalize(stateP) {
  const state = stateP;
  keccakFinalize(state.s, state.pos, Shake256Rate, 0x1f);
  state.pos = Shake256Rate;
}

export function shake256SqueezeBlocks(out, outputOffset, nBlocks, state) {
  keccakSqueezeBlocks(out, outputOffset, nBlocks, state.s, Shake256Rate);
}
