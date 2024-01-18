import pkg from 'randombytes';
import { SHAKE } from 'sha3';

const Shake128Rate = 168;
const Shake256Rate = 136;
const Stream128BlockBytes = Shake128Rate;
const Stream256BlockBytes = Shake256Rate;

const SeedBytes = 32;
const CRHBytes = 64;
const N = 256;
const Q = 8380417;
const QInv = 58728449;
const D = 13;

const K = 8;
const L = 7;
const ETA = 2;
const TAU = 60;
const BETA = 120;
const GAMMA1 = 1 << 19;
const GAMMA2 = Math.floor((Q - 1) / 32);
const OMEGA = 75;

const PolyT1PackedBytes = 320;
const PolyT0PackedBytes = 416;
const PolyETAPackedBytes = 96;
const PolyZPackedBytes = 640;
const PolyVecHPackedBytes = OMEGA + K;
const PolyW1PackedBytes = 128;

const CryptoPublicKeyBytes = SeedBytes + K * PolyT1PackedBytes;
const CryptoSecretKeyBytes =
  3 * SeedBytes + L * PolyETAPackedBytes + K * PolyETAPackedBytes + K * PolyT0PackedBytes;
const CryptoBytes = SeedBytes + L * PolyZPackedBytes + PolyVecHPackedBytes;

const PolyUniformNBlocks = Math.floor((768 + Stream128BlockBytes - 1) / Stream128BlockBytes);
const PolyUniformETANBlocks = Math.floor((136 + Stream256BlockBytes - 1) / Stream256BlockBytes);
const PolyUniformGamma1NBlocks = Math.floor((PolyZPackedBytes + Stream256BlockBytes - 1) / Stream256BlockBytes);

const zetas = [
  0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251, -2091905, 3119733, -2884855,
  3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549, -2118186, -3859737,
  -1399561, -3277672, 1757237, -19422, 4010497, 280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516,
  3915439, -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
  -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598, -1000202,
  -3190144, -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
  -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992, 44288,
  -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856, 189548, -3553272,
  3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669, -1584928, -812732, -1439742, -3019102, -3881060,
  -3628969, 3839961, 2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439,
  -1235728, 3513181, -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
  -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297, 286988, -2437823, 4108315,
  3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016,
  1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100,
  1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
  -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455, -164721, 1957272,
  3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107, -3038916, 3523897,
  3866901, 269760, 2213111, -975884, 1717735, 472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646,
  -3833893, -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
  -1362209, 3937738, 1400424, -846154, 1976782,
];

const NRounds = 24;

const KeccakFRoundConstants = BigUint64Array.from([
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

class KeccakState {
  constructor() {
    this.s = new BigUint64Array(25);
    this.pos = 0;
  }
}

function ROL(a, offset) {
  return BigInt.asUintN(64, BigInt.asUintN(64, a << offset) ^ (a >> (64n - offset)));
}

function load64(x, xOffset) {
  let r = BigInt(0);

  for (let i = 0; i < 8; i++) r = BigInt.asUintN(64, r | BigInt.asUintN(64, BigInt(x[xOffset + i]) << BigInt(8 * i)));

  return r;
}

function store64(xP, xOffset, u) {
  const x = xP;
  for (let i = 0; i < 8; i++) x[xOffset + i] = Number((u >> BigInt(8 * i)) & 0xffn);
}

function KeccakF1600StatePermute(stateP) {
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

function keccakInit(sP) {
  const s = sP;
  for (let i = 0; i < 25; i++) s[i] = 0n;
}

function keccakAbsorb(sP, posP, r, input) {
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

function keccakFinalize(sP, pos, r, p) {
  const s = sP;
  s[Math.floor(pos / 8)] = BigInt.asUintN(64, s[Math.floor(pos / 8)] ^ (BigInt(p) << BigInt(8 * (pos % 8))));
  s[Math.floor(r / 8) - 1] = BigInt.asUintN(64, s[Math.floor(r / 8) - 1] ^ (1n << 63n));
}

function keccakSqueeze(outP, s, posP, r) {
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

function keccakAbsorbOnce(sP, r, input, p) {
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

function keccakSqueezeBlocks(output, outputOffsetP, nBlocksP, s, r) {
  let nBlocks = nBlocksP;
  let outputOffset = outputOffsetP;
  while (nBlocks) {
    KeccakF1600StatePermute(s);
    for (let i = 0; i < Math.floor(r / 8); i++) store64(output, outputOffset + 8 * i, s[i]);
    outputOffset += r;
    nBlocks -= 1;
  }
}

function shake128Init(stateP) {
  const state = stateP;
  keccakInit(state.s);
  state.pos = 0;
}

function shake128Absorb(stateP, input) {
  const state = stateP;
  state.pos = keccakAbsorb(state.s, state.pos, Shake128Rate, input);
}

function shake128Finalize(stateP) {
  const state = stateP;
  keccakFinalize(state.s, state.pos, Shake128Rate, 0x1f);
  state.pos = Shake128Rate;
}

function shake128Squeeze(out, stateP) {
  const state = stateP;
  state.pos = keccakSqueeze(out, state.s, state.pos, Shake128Rate);
}

function shake128AbsorbOnce(stateP, input) {
  const state = stateP;
  keccakAbsorbOnce(state.s, Shake128Rate, input, 0x1f);
  state.pos = Shake128Rate;
}

function shake128SqueezeBlocks(out, outputOffset, nBlocks, state) {
  keccakSqueezeBlocks(out, outputOffset, nBlocks, state.s, Shake128Rate);
}

function shake256Init(stateP) {
  const state = stateP;
  keccakInit(state.s);
  state.pos = 0;
}

function shake256Absorb(stateP, input) {
  const state = stateP;
  state.pos = keccakAbsorb(state.s, state.pos, Shake256Rate, input);
}

function shake256Finalize(stateP) {
  const state = stateP;
  keccakFinalize(state.s, state.pos, Shake256Rate, 0x1f);
  state.pos = Shake256Rate;
}

function shake256SqueezeBlocks(out, outputOffset, nBlocks, state) {
  keccakSqueezeBlocks(out, outputOffset, nBlocks, state.s, Shake256Rate);
}

function dilithiumShake128StreamInit(state, seed, nonce) {
  if (seed.length !== SeedBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${SeedBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake128Init(state);
  shake128Absorb(state, seed);
  shake128Absorb(state, t);
  shake128Finalize(state);
}

function dilithiumShake256StreamInit(state, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${CRHBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Absorb(state, t);
  shake256Finalize(state);
}

function montgomeryReduce(a) {
  let t = BigInt.asIntN(32, BigInt.asIntN(64, BigInt.asIntN(32, a)) * BigInt(QInv));
  t = BigInt.asIntN(32, (a - t * BigInt(Q)) >> 32n);
  return t;
}

function reduce32(a) {
  let t = (a + (1 << 22)) >> 23;
  t = a - t * Q;
  return t;
}

function cAddQ(a) {
  let ar = a;
  ar += (ar >> 31) & Q;
  return ar;
}

function ntt(a) {
  let k = 0;
  let j = 0;

  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = zetas[++k];
      for (j = start; j < start + len; ++j) {
        const t = Number(montgomeryReduce(BigInt.asIntN(64, BigInt(zeta) * BigInt(a[j + len]))));
        a[j + len] = a[j] - t; // eslint-disable-line no-param-reassign
        // eslint-disable-next-line
        a[j] = a[j] + t;
      }
    }
  }
}

function invNTTToMont(a) {
  const f = 41978n; // mont^2/256
  let j = 0;
  let k = 256;

  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = BigInt.asIntN(32, BigInt(-zetas[--k]));
      for (j = start; j < start + len; ++j) {
        const t = a[j];
        a[j] = t + a[j + len]; // eslint-disable-line no-param-reassign
        a[j + len] = t - a[j + len]; // eslint-disable-line no-param-reassign
        a[j + len] = Number(montgomeryReduce(BigInt.asIntN(64, zeta * BigInt(a[j + len])))); // eslint-disable-line no-param-reassign
      }
    }
  }
  // eslint-disable-next-line no-shadow
  for (let j = 0; j < N; ++j) {
    a[j] = Number(montgomeryReduce(BigInt.asIntN(64, f * BigInt(a[j])))); // eslint-disable-line no-param-reassign
  }
}

function power2round(a0p, i, a) {
  const a0 = a0p;
  const a1 = (a + (1 << (D - 1)) - 1) >> D;
  a0[i] = a - (a1 << D);
  return a1;
}

function decompose(a0p, i, a) {
  const a0 = a0p;
  let a1 = (a + 127) >> 7;
  a1 = (a1 * 1025 + (1 << 21)) >> 22;
  a1 &= 15;

  a0[i] = a - a1 * 2 * GAMMA2;
  a0[i] -= (((Q - 1) / 2 - a0[i]) >> 31) & Q;
  return a1;
}

function makeHint(a0, a1) {
  if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 === -GAMMA2 && a1 !== 0)) return 1;

  return 0;
}

function useHint(a, hint) {
  const a0 = new Int32Array(1);
  const a1 = decompose(a0, 0, a);

  if (hint === 0) return a1;

  if (a0[0] > 0) return (a1 + 1) & 15;
  return (a1 - 1) & 15;
}

class Poly {
  constructor() {
    this.coeffs = new Int32Array(N);
  }

  copy(poly) {
    for (let i = N - 1; i >= 0; i--) {
      this.coeffs[i] = poly.coeffs[i];
    }
  }
}

function polyReduce(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = reduce32(a.coeffs[i]);
}

function polyCAddQ(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = cAddQ(a.coeffs[i]);
}

function polyAdd(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
}

function polySub(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
}

function polyShiftL(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] <<= D;
}

function polyNTT(a) {
  ntt(a.coeffs);
}

function polyInvNTTToMont(a) {
  invNTTToMont(a.coeffs);
}

function polyPointWiseMontgomery(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = Number(montgomeryReduce(BigInt(a.coeffs[i]) * BigInt(b.coeffs[i])));
}

function polyPower2round(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = power2round(a0.coeffs, i, a.coeffs[i]);
}

function polyDecompose(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = decompose(a0.coeffs, i, a.coeffs[i]);
}

function polyMakeHint(hp, a0, a1) {
  let s = 0;
  const h = hp;
  for (let i = 0; i < N; ++i) {
    h.coeffs[i] = makeHint(a0.coeffs[i], a1.coeffs[i]);
    s += h.coeffs[i];
  }

  return s;
}

function polyUseHint(bp, a, h) {
  const b = bp;
  for (let i = 0; i < N; ++i) {
    b.coeffs[i] = useHint(a.coeffs[i], h.coeffs[i]);
  }
}

function polyChkNorm(a, b) {
  if (b > Math.floor((Q - 1) / 8)) {
    return 1;
  }

  for (let i = 0; i < N; i++) {
    let t = a.coeffs[i] >> 31;
    t = a.coeffs[i] - (t & (2 * a.coeffs[i]));

    if (t >= b) {
      return 1;
    }
  }

  return 0;
}

function rejUniform(ap, aOffset, len, buf, bufLen) {
  let ctr = 0;
  let pos = 0;
  const a = ap;
  while (ctr < len && pos + 3 <= bufLen) {
    let t = buf[pos++];
    t |= buf[pos++] << 8;
    t |= buf[pos++] << 16;
    t &= 0x7fffff;

    if (t < Q) {
      a[aOffset + ctr++] = t;
    }
  }

  return ctr;
}

function polyUniform(a, seed, nonce) {
  let off = 0;
  let bufLen = PolyUniformNBlocks * Stream128BlockBytes;
  const buf = new Uint8Array(PolyUniformNBlocks * Stream128BlockBytes + 2);

  const state = new KeccakState();
  dilithiumShake128StreamInit(state, seed, nonce);
  shake128SqueezeBlocks(buf, off, PolyUniformNBlocks, state);

  let ctr = rejUniform(a.coeffs, 0, N, buf, bufLen);

  while (ctr < N) {
    off = bufLen % 3;
    for (let i = 0; i < off; ++i) buf[i] = buf[bufLen - off + i];

    shake128SqueezeBlocks(buf, off, 1, state);
    bufLen = Stream128BlockBytes + off;
    ctr += rejUniform(a.coeffs, ctr, N - ctr, buf, bufLen);
  }
}

function rejEta(aP, aOffset, len, buf, bufLen) {
  let ctr;
  let pos;
  let t0;
  let t1;
  const a = aP;
  ctr = 0;
  pos = 0;
  while (ctr < len && pos < bufLen) {
    t0 = buf[pos] & 0x0f;
    t1 = buf[pos++] >> 4;

    if (t0 < 15) {
      t0 -= ((205 * t0) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t0;
    }
    if (t1 < 15 && ctr < len) {
      t1 -= ((205 * t1) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t1;
    }
  }

  return ctr;
}

function polyUniformEta(a, seed, nonce) {
  let ctr;
  const bufLen = PolyUniformETANBlocks * Stream256BlockBytes;
  const buf = new Uint8Array(bufLen);

  const state = new KeccakState();
  dilithiumShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformETANBlocks, state);

  ctr = rejEta(a.coeffs, 0, N, buf, bufLen);
  while (ctr < N) {
    shake256SqueezeBlocks(buf, 0, 1, state);
    ctr += rejEta(a.coeffs, ctr, N - ctr, buf, Stream256BlockBytes);
  }
}

function polyZUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r.coeffs[2 * i] = a[aOffset + 5 * i];
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 1] << 8;
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 2] << 16;
    r.coeffs[2 * i] &= 0xfffff;

    r.coeffs[2 * i + 1] = a[aOffset + 5 * i + 2] >> 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 3] << 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 4] << 12;
    r.coeffs[2 * i] &= 0xfffff;

    r.coeffs[2 * i] = GAMMA1 - r.coeffs[2 * i];
    r.coeffs[2 * i + 1] = GAMMA1 - r.coeffs[2 * i + 1];
  }
}

function polyUniformGamma1(a, seed, nonce) {
  const buf = new Uint8Array(PolyUniformGamma1NBlocks * Stream256BlockBytes);

  const state = new KeccakState();
  dilithiumShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformGamma1NBlocks, state);
  polyZUnpack(a, buf, 0);
}

function polyChallenge(cP, seed) {
  let b;
  let pos;
  const c = cP;
  const buf = new Uint8Array(Shake256Rate);

  const state = new KeccakState();
  shake256Init(state);
  shake256Absorb(state, seed.slice(0, SeedBytes));
  shake256Finalize(state);
  shake256SqueezeBlocks(buf, 0, 1, state);

  let signs = 0n;
  for (let i = 0; i < 8; ++i) {
    signs = BigInt.asUintN(64, signs | (BigInt(buf[i]) << BigInt(8 * i)));
  }
  pos = 8;

  for (let i = 0; i < N; ++i) {
    c.coeffs[i] = 0;
  }
  for (let i = N - TAU; i < N; ++i) {
    do {
      if (pos >= Shake256Rate) {
        shake256SqueezeBlocks(buf, 0, 1, state);
        pos = 0;
      }

      b = buf[pos++];
    } while (b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = Number(1n - 2n * (signs & 1n));
    signs >>= 1n;
  }
}

function polyEtaPack(rP, rOffset, a) {
  const t = new Uint8Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = ETA - a.coeffs[8 * i];
    t[1] = ETA - a.coeffs[8 * i + 1];
    t[2] = ETA - a.coeffs[8 * i + 2];
    t[3] = ETA - a.coeffs[8 * i + 3];
    t[4] = ETA - a.coeffs[8 * i + 4];
    t[5] = ETA - a.coeffs[8 * i + 5];
    t[6] = ETA - a.coeffs[8 * i + 6];
    t[7] = ETA - a.coeffs[8 * i + 7];

    r[rOffset + 3 * i] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[rOffset + 3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[rOffset + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
}

function polyEtaUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = (a[aOffset + 3 * i] >> 0) & 7;
    r.coeffs[8 * i + 1] = (a[aOffset + 3 * i] >> 3) & 7;
    r.coeffs[8 * i + 2] = ((a[aOffset + 3 * i] >> 6) | (a[aOffset + 3 * i + 1] << 2)) & 7;
    r.coeffs[8 * i + 3] = (a[aOffset + 3 * i + 1] >> 1) & 7;
    r.coeffs[8 * i + 4] = (a[aOffset + 3 * i + 1] >> 4) & 7;
    r.coeffs[8 * i + 5] = ((a[aOffset + 3 * i + 1] >> 7) | (a[aOffset + 3 * i + 2] << 1)) & 7;
    r.coeffs[8 * i + 6] = (a[aOffset + 3 * i + 2] >> 2) & 7;
    r.coeffs[8 * i + 7] = (a[aOffset + 3 * i + 2] >> 5) & 7;

    r.coeffs[8 * i] = ETA - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = ETA - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = ETA - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = ETA - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = ETA - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = ETA - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = ETA - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = ETA - r.coeffs[8 * i + 7];
  }
}

function polyT1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r[rOffset + 5 * i] = a.coeffs[4 * i] >> 0;
    r[rOffset + 5 * i + 1] = (a.coeffs[4 * i] >> 8) | (a.coeffs[4 * i + 1] << 2);
    r[rOffset + 5 * i + 2] = (a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4);
    r[rOffset + 5 * i + 3] = (a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6);
    r[rOffset + 5 * i + 4] = a.coeffs[4 * i + 3] >> 2;
  }
}

function polyT1Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r.coeffs[4 * i] = ((a[aOffset + 5 * i] >> 0) | (a[aOffset + 5 * i + 1] << 8)) & 0x3ff;
    r.coeffs[4 * i + 1] = ((a[aOffset + 5 * i + 1] >> 2) | (a[aOffset + 5 * i + 2] << 6)) & 0x3ff;
    r.coeffs[4 * i + 2] = ((a[aOffset + 5 * i + 2] >> 4) | (a[aOffset + 5 * i + 3] << 4)) & 0x3ff;
    r.coeffs[4 * i + 3] = ((a[aOffset + 5 * i + 3] >> 6) | (a[aOffset + 5 * i + 4] << 2)) & 0x3ff;
  }
}

function polyT0Pack(rP, rOffset, a) {
  const t = new Uint32Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = (1 << (D - 1)) - a.coeffs[8 * i];
    t[1] = (1 << (D - 1)) - a.coeffs[8 * i + 1];
    t[2] = (1 << (D - 1)) - a.coeffs[8 * i + 2];
    t[3] = (1 << (D - 1)) - a.coeffs[8 * i + 3];
    t[4] = (1 << (D - 1)) - a.coeffs[8 * i + 4];
    t[5] = (1 << (D - 1)) - a.coeffs[8 * i + 5];
    t[6] = (1 << (D - 1)) - a.coeffs[8 * i + 6];
    t[7] = (1 << (D - 1)) - a.coeffs[8 * i + 7];

    r[rOffset + 13 * i] = t[0]; // eslint-disable-line prefer-destructuring
    r[rOffset + 13 * i + 1] = t[0] >> 8;
    r[rOffset + 13 * i + 1] |= t[1] << 5;
    r[rOffset + 13 * i + 2] = t[1] >> 3;
    r[rOffset + 13 * i + 3] = t[1] >> 11;
    r[rOffset + 13 * i + 3] |= t[2] << 2;
    r[rOffset + 13 * i + 4] = t[2] >> 6;
    r[rOffset + 13 * i + 4] |= t[3] << 7;
    r[rOffset + 13 * i + 5] = t[3] >> 1;
    r[rOffset + 13 * i + 6] = t[3] >> 9;
    r[rOffset + 13 * i + 6] |= t[4] << 4;
    r[rOffset + 13 * i + 7] = t[4] >> 4;
    r[rOffset + 13 * i + 8] = t[4] >> 12;
    r[rOffset + 13 * i + 8] |= t[5] << 1;
    r[rOffset + 13 * i + 9] = t[5] >> 7;
    r[rOffset + 13 * i + 9] |= t[6] << 6;
    r[rOffset + 13 * i + 10] = t[6] >> 2;
    r[rOffset + 13 * i + 11] = t[6] >> 10;
    r[rOffset + 13 * i + 11] |= t[7] << 3;
    r[rOffset + 13 * i + 12] = t[7] >> 5;
  }
}

function polyT0Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = a[aOffset + 13 * i];
    r.coeffs[8 * i] |= a[aOffset + 13 * i + 1] << 8;
    r.coeffs[8 * i] &= 0x1fff;

    r.coeffs[8 * i + 1] = a[aOffset + 13 * i + 1] >> 5;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 2] << 3;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 3] << 11;
    r.coeffs[8 * i + 1] &= 0x1fff;

    r.coeffs[8 * i + 2] = a[aOffset + 13 * i + 3] >> 2;
    r.coeffs[8 * i + 2] |= a[aOffset + 13 * i + 4] << 6;
    r.coeffs[8 * i + 2] &= 0x1fff;

    r.coeffs[8 * i + 3] = a[aOffset + 13 * i + 4] >> 7;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 5] << 1;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 6] << 9;
    r.coeffs[8 * i + 3] &= 0x1fff;

    r.coeffs[8 * i + 4] = a[aOffset + 13 * i + 6] >> 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 7] << 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 8] << 12;
    r.coeffs[8 * i + 4] &= 0x1fff;

    r.coeffs[8 * i + 5] = a[aOffset + 13 * i + 8] >> 1;
    r.coeffs[8 * i + 5] |= a[aOffset + 13 * i + 9] << 7;
    r.coeffs[8 * i + 5] &= 0x1fff;

    r.coeffs[8 * i + 6] = a[aOffset + 13 * i + 9] >> 6;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 10] << 2;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 11] << 10;
    r.coeffs[8 * i + 6] &= 0x1fff;

    r.coeffs[8 * i + 7] = a[aOffset + 13 * i + 11] >> 3;
    r.coeffs[8 * i + 7] |= a[aOffset + 13 * i + 12] << 5;
    r.coeffs[8 * i + 7] &= 0x1fff;

    r.coeffs[8 * i] = (1 << (D - 1)) - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = (1 << (D - 1)) - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = (1 << (D - 1)) - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = (1 << (D - 1)) - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = (1 << (D - 1)) - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = (1 << (D - 1)) - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = (1 << (D - 1)) - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = (1 << (D - 1)) - r.coeffs[8 * i + 7];
  }
}

function polyZPack(rP, rOffset, a) {
  const t = new Uint32Array(4);
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    t[0] = GAMMA1 - a.coeffs[2 * i];
    t[1] = GAMMA1 - a.coeffs[2 * i + 1];

    r[rOffset + 5 * i] = t[0]; // eslint-disable-line prefer-destructuring
    r[rOffset + 5 * i + 1] = t[0] >> 8;
    r[rOffset + 5 * i + 2] = t[0] >> 16;
    r[rOffset + 5 * i + 2] |= t[1] << 4;
    r[rOffset + 5 * i + 3] = t[1] >> 4;
    r[rOffset + 5 * i + 4] = t[1] >> 12;
  }
}

function polyW1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r[rOffset + i] = a.coeffs[2 * i] | (a.coeffs[2 * i + 1] << 4);
  }
}

class PolyVecK {
  constructor() {
    this.vec = new Array(K).fill().map(() => new Poly());
  }
}

class PolyVecL {
  constructor() {
    this.vec = new Array(L).fill().map(() => new Poly());
  }

  copy(polyVecL) {
    for (let i = L - 1; i >= 0; i--) {
      this.vec[i].copy(polyVecL.vec[i]);
    }
  }
}

function polyVecMatrixExpand(mat, rho) {
  if (rho.length !== SeedBytes) {
    throw new Error(`invalid rho length ${rho.length} | Expected length ${SeedBytes}`);
  }
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < L; ++j) {
      polyUniform(mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

function polyVecMatrixPointWiseMontgomery(t, mat, v) {
  for (let i = 0; i < K; ++i) {
    polyVecLPointWiseAccMontgomery(t.vec[i], mat[i], v); // eslint-disable-line no-use-before-define
  }
}

function polyVecLUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecLUniformGamma1(v, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformGamma1(v.vec[i], seed, L * nonce + i);
  }
}

function polyVecLReduce(v) {
  for (let i = 0; i < L; i++) {
    polyReduce(v.vec[i]);
  }
}

function polyVecLAdd(w, u, v) {
  for (let i = 0; i < L; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecLNTT(v) {
  for (let i = 0; i < L; ++i) {
    polyNTT(v.vec[i]);
  }
}

function polyVecLInvNTTToMont(v) {
  for (let i = 0; i < L; ++i) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecLPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < L; ++i) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecLPointWiseAccMontgomery(w, u, v) {
  const t = new Poly();
  polyPointWiseMontgomery(w, u.vec[0], v.vec[0]);
  for (let i = 1; i < L; i++) {
    polyPointWiseMontgomery(t, u.vec[i], v.vec[i]);
    polyAdd(w, w, t);
  }
}

function polyVecLChkNorm(v, bound) {
  for (let i = 0; i < L; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  for (let i = 0; i < K; ++i) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecKReduce(v) {
  for (let i = 0; i < K; ++i) {
    polyReduce(v.vec[i]);
  }
}

function polyVecKCAddQ(v) {
  for (let i = 0; i < K; ++i) {
    polyCAddQ(v.vec[i]);
  }
}

function polyVecKAdd(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKSub(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polySub(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKShiftL(v) {
  for (let i = 0; i < K; ++i) {
    polyShiftL(v.vec[i]);
  }
}

function polyVecKNTT(v) {
  for (let i = 0; i < K; i++) {
    polyNTT(v.vec[i]);
  }
}

function polyVecKInvNTTToMont(v) {
  for (let i = 0; i < K; i++) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecKPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < K; i++) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecKChkNorm(v, bound) {
  for (let i = 0; i < K; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKPower2round(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyPower2round(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKDecompose(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyDecompose(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKMakeHint(h, v0, v1) {
  let s = 0;
  for (let i = 0; i < K; i++) {
    s += polyMakeHint(h.vec[i], v0.vec[i], v1.vec[i]);
  }
  return s;
}

function polyVecKUseHint(w, u, h) {
  for (let i = 0; i < K; ++i) {
    polyUseHint(w.vec[i], u.vec[i], h.vec[i]);
  }
}

function polyVecKPackW1(r, w1) {
  for (let i = 0; i < K; ++i) {
    polyW1Pack(r, i * PolyW1PackedBytes, w1.vec[i]);
  }
}

function packPk(pkp, rho, t1) {
  const pk = pkp;
  for (let i = 0; i < SeedBytes; ++i) {
    pk[i] = rho[i];
  }
  for (let i = 0; i < K; ++i) {
    polyT1Pack(pk, SeedBytes + i * PolyT1PackedBytes, t1.vec[i]);
  }
}

function unpackPk(rhop, t1, pk) {
  const rho = rhop;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = pk[i];
  }

  for (let i = 0; i < K; ++i) {
    polyT1Unpack(t1.vec[i], pk, SeedBytes + i * PolyT1PackedBytes);
  }
}

function packSk(skp, rho, tr, key, t0, s1, s2) {
  let skOffset = 0;
  const sk = skp;
  for (let i = 0; i < SeedBytes; ++i) {
    sk[i] = rho[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    sk[skOffset + i] = key[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    sk[skOffset + i] = tr[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s1.vec[i]);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s2.vec[i]);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Pack(sk, skOffset + i * PolyT0PackedBytes, t0.vec[i]);
  }
}

function unpackSk(rhoP, trP, keyP, t0, s1, s2, sk) {
  let skOffset = 0;
  const rho = rhoP;
  const tr = trP;
  const key = keyP;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    key[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    tr[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaUnpack(s1.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaUnpack(s2.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Unpack(t0.vec[i], sk, skOffset + i * PolyT0PackedBytes);
  }
}

function packSig(sigP, c, z, h) {
  let sigOffset = 0;
  const sig = sigP;
  for (let i = 0; i < SeedBytes; ++i) {
    sig[i] = c[i];
  }
  sigOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyZPack(sig, sigOffset + i * PolyZPackedBytes, z.vec[i]);
  }
  sigOffset += L * PolyZPackedBytes;

  for (let i = 0; i < OMEGA + K; ++i) {
    sig[sigOffset + i] = 0;
  }

  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      if (h.vec[i].coeffs[j] !== 0) {
        sig[sigOffset + k++] = j;
      }
    }

    sig[sigOffset + OMEGA + i] = k;
  }
}

function unpackSig(cP, z, hP, sig) {
  let sigOffset = 0;
  const c = cP;
  const h = hP;
  for (let i = 0; i < SeedBytes; ++i) {
    c[i] = sig[i];
  }
  sigOffset += SeedBytes;

  for (let i = 0; i < L; ++i) {
    polyZUnpack(z.vec[i], sig, sigOffset + i * PolyZPackedBytes);
  }
  sigOffset += L * PolyZPackedBytes;

  /* Decode h */
  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      h.vec[i].coeffs[j] = 0;
    }

    if (sig[sigOffset + OMEGA + i] < k || sig[sigOffset + OMEGA + i] > OMEGA) {
      return 1;
    }

    for (let j = k; j < sig[sigOffset + OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if (j > k && sig[sigOffset + j] <= sig[sigOffset + j - 1]) {
        return 1;
      }
      h.vec[i].coeffs[sig[sigOffset + j]] = 1;
    }

    k = sig[sigOffset + OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for (let j = k; j < OMEGA; ++j) {
    if (sig[sigOffset + j]) {
      return 1;
    }
  }

  return 0;
}

const randomBytes = pkg;

function cryptoSignKeypair(passedSeed, pk, sk) {
  try {
    if (pk.length !== CryptoPublicKeyBytes) {
      throw new Error(`invalid pk length ${pk.length} | Expected length ${CryptoPublicKeyBytes}`);
    }
    if (sk.length !== CryptoSecretKeyBytes) {
      throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error(`pk/sk cannot be null`);
    } else {
      throw new Error(`${e.message}`);
    }
  }
  // eslint-disable-next-line no-unused-vars
  const mat = new Array(K).fill().map((_) => new PolyVecL());
  const s1 = new PolyVecL();
  const s2 = new PolyVecK();
  const t1 = new PolyVecK();
  const t0 = new PolyVecK();

  // Get randomness for rho, rhoPrime and key
  const seed = passedSeed || randomBytes(SeedBytes);

  const state = new SHAKE(256);
  let outputLength = 2 * SeedBytes + CRHBytes;
  state.update(seed);
  const seedBuf = state.digest({ buffer: Buffer.alloc(outputLength) });
  const rho = seedBuf.slice(0, SeedBytes);
  const rhoPrime = seedBuf.slice(SeedBytes, SeedBytes + CRHBytes);
  const key = seedBuf.slice(SeedBytes + CRHBytes);

  // Expand matrix
  polyVecMatrixExpand(mat, rho);

  // Sample short vectors s1 and s2
  polyVecLUniformEta(s1, rhoPrime, 0);
  polyVecKUniformEta(s2, rhoPrime, L);

  // Matrix-vector multiplication
  const s1hat = new PolyVecL();
  s1hat.copy(s1);
  polyVecLNTT(s1hat);
  polyVecMatrixPointWiseMontgomery(t1, mat, s1hat);
  polyVecKReduce(t1);
  polyVecKInvNTTToMont(t1);

  // Add error vector s2
  polyVecKAdd(t1, t1, s2);

  // Extract t1 and write public key
  polyVecKCAddQ(t1);
  polyVecKPower2round(t1, t0, t1);
  packPk(pk, rho, t1);

  // Compute H(rho, t1) and write secret key
  const hasher = new SHAKE(256);
  outputLength = SeedBytes;
  hasher.update(Buffer.from(pk, 'hex'));
  const tr = new Uint8Array(hasher.digest());
  packSk(sk, rho, tr, key, t0, s1, s2);

  return seed;
}

function cryptoSignSignature(sig, m, sk, randomizedSigning) {
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const rho = new Uint8Array(SeedBytes);
  const tr = new Uint8Array(SeedBytes);
  const key = new Uint8Array(SeedBytes);
  let rhoPrime = new Uint8Array(CRHBytes);
  let nonce = 0;
  let state = null;
  const mat = Array(K)
    .fill()
    // eslint-disable-next-line no-unused-vars
    .map((_) => new PolyVecL());
  const s1 = new PolyVecL();
  const y = new PolyVecL();
  const z = new PolyVecL();
  const t0 = new PolyVecK();
  const s2 = new PolyVecK();
  const w1 = new PolyVecK();
  const w0 = new PolyVecK();
  const h = new PolyVecK();
  const cp = new Poly();

  unpackSk(rho, tr, key, t0, s1, s2, sk);

  state = new SHAKE(256);
  let outputLength = CRHBytes;
  state.update(Buffer.from(tr, 'hex'));
  state.update(Buffer.from(m, 'hex'));
  const mu = new Uint8Array(state.digest({ buffer: Buffer.alloc(outputLength) }));

  if (randomizedSigning) rhoPrime = new Uint8Array(randomBytes(CRHBytes));
  else {
    state = new SHAKE(256);
    outputLength = CRHBytes;
    state.update(Buffer.from(key, 'hex'));
    state.update(Buffer.from(mu, 'hex'));
    rhoPrime.set(state.digest({ buffer: Buffer.alloc(outputLength) }));
  }

  polyVecMatrixExpand(mat, rho);
  polyVecLNTT(s1);
  polyVecKNTT(s2);
  polyVecKNTT(t0);

  // eslint-disable-next-line no-constant-condition
  while (true) {
    polyVecLUniformGamma1(y, rhoPrime, nonce++);
    // Matrix-vector multiplication
    z.copy(y);
    polyVecLNTT(z);
    polyVecMatrixPointWiseMontgomery(w1, mat, z);
    polyVecKReduce(w1);
    polyVecKInvNTTToMont(w1);

    // Decompose w and call the random oracle
    polyVecKCAddQ(w1);
    polyVecKDecompose(w1, w0, w1);
    polyVecKPackW1(sig, w1);

    state = new SHAKE(256);
    outputLength = SeedBytes;
    state.update(Buffer.from(mu, 'hex'));
    state.update(Buffer.from(sig.slice(0, K * PolyW1PackedBytes)), 'hex');
    sig.set(state.digest({ buffer: Buffer.alloc(outputLength) }));

    polyChallenge(cp, sig);
    polyNTT(cp);

    // Compute z, reject if it reveals secret
    polyVecLPointWisePolyMontgomery(z, cp, s1);
    polyVecLInvNTTToMont(z);
    polyVecLAdd(z, z, y);
    polyVecLReduce(z);
    if (polyVecLChkNorm(z, GAMMA1 - BETA) !== 0) {
      continue; // eslint-disable-line no-continue
    }

    polyVecKPointWisePolyMontgomery(h, cp, s2);
    polyVecKInvNTTToMont(h);
    polyVecKSub(w0, w0, h);
    polyVecKReduce(w0);
    if (polyVecKChkNorm(w0, GAMMA2 - BETA) !== 0) {
      continue; // eslint-disable-line no-continue
    }

    polyVecKPointWisePolyMontgomery(h, cp, t0);
    polyVecKInvNTTToMont(h);
    polyVecKReduce(h);
    if (polyVecKChkNorm(h, GAMMA2) !== 0) {
      continue; // eslint-disable-line no-continue
    }

    polyVecKAdd(w0, w0, h);
    const n = polyVecKMakeHint(h, w0, w1);
    if (n > OMEGA) {
      continue; // eslint-disable-line no-continue
    }

    packSig(sig, sig, z, h);
    return 0;
  }
}

function cryptoSign(msg, sk, randomizedSigning) {
  const sm = new Uint8Array(CryptoBytes + msg.length);
  const mLen = msg.length;
  for (let i = 0; i < mLen; ++i) {
    sm[CryptoBytes + mLen - 1 - i] = msg[mLen - 1 - i];
  }
  const result = cryptoSignSignature(sm, msg, sk, randomizedSigning);

  if (result !== 0) {
    throw new Error('failed to sign');
  }
  return sm;
}

function cryptoSignVerify(sig, m, pk) {
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(SeedBytes);
  const c2 = new Uint8Array(SeedBytes);
  const cp = new Poly();
  // eslint-disable-next-line no-unused-vars
  const mat = new Array(K).fill().map((_) => new PolyVecL());
  const z = new PolyVecL();
  const t1 = new PolyVecK();
  const w1 = new PolyVecK();
  const h = new PolyVecK();

  if (sig.length !== CryptoBytes) {
    return false;
  }
  if (pk.length !== CryptoPublicKeyBytes) {
    return false;
  }

  unpackPk(rho, t1, pk);
  if (unpackSig(c, z, h, sig)) {
    return false;
  }
  if (polyVecLChkNorm(z, GAMMA1 - BETA)) {
    return false;
  }

  /* Compute CRH(H(rho, t1), msg) */
  let state = new SHAKE(256);
  let outputLength = SeedBytes;
  state.update(pk.slice(0, CryptoPublicKeyBytes));
  mu.set(state.digest({ buffer: Buffer.alloc(outputLength) }));

  state = new SHAKE(256);
  outputLength = CRHBytes;
  state.update(Buffer.from(mu.slice(0, SeedBytes), 'hex'));
  state.update(Buffer.from(m, 'hex'));
  mu.set(state.digest({ buffer: Buffer.alloc(outputLength) }));

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  polyChallenge(cp, c);
  polyVecMatrixExpand(mat, rho);

  polyVecLNTT(z);
  polyVecMatrixPointWiseMontgomery(w1, mat, z);

  polyNTT(cp);
  polyVecKShiftL(t1);
  polyVecKNTT(t1);
  polyVecKPointWisePolyMontgomery(t1, cp, t1);

  polyVecKSub(w1, w1, t1);
  polyVecKReduce(w1);
  polyVecKInvNTTToMont(w1);

  /* Reconstruct w1 */
  polyVecKCAddQ(w1);
  polyVecKUseHint(w1, w1, h);
  polyVecKPackW1(buf, w1);

  /* Call random oracle and verify challenge */
  state = new SHAKE(256);
  outputLength = SeedBytes;
  state.update(Buffer.from(mu, 'hex'));
  state.update(Buffer.from(buf, 'hex'));
  c2.set(state.digest({ buffer: Buffer.alloc(outputLength) }));

  for (i = 0; i < SeedBytes; ++i) if (c[i] !== c2[i]) return false;
  return true;
}

function cryptoSignOpen(sm, pk) {
  if (sm.length < CryptoBytes) {
    return undefined;
  }

  const sig = sm.slice(0, CryptoBytes);
  const msg = sm.slice(CryptoBytes);
  if (!cryptoSignVerify(sig, msg, pk)) {
    return undefined;
  }

  return msg;
}

export { BETA, CRHBytes, CryptoBytes, CryptoPublicKeyBytes, CryptoSecretKeyBytes, D, ETA, GAMMA1, GAMMA2, K, KeccakF1600StatePermute, KeccakFRoundConstants, KeccakState, L, N, NRounds, OMEGA, Poly, PolyETAPackedBytes, PolyT0PackedBytes, PolyT1PackedBytes, PolyUniformETANBlocks, PolyUniformGamma1NBlocks, PolyUniformNBlocks, PolyVecHPackedBytes, PolyVecK, PolyVecL, PolyW1PackedBytes, PolyZPackedBytes, Q, QInv, ROL, SeedBytes, Shake128Rate, Shake256Rate, Stream128BlockBytes, Stream256BlockBytes, TAU, cAddQ, cryptoSign, cryptoSignKeypair, cryptoSignOpen, cryptoSignSignature, cryptoSignVerify, decompose, dilithiumShake128StreamInit, dilithiumShake256StreamInit, invNTTToMont, keccakAbsorb, keccakAbsorbOnce, keccakFinalize, keccakInit, keccakSqueeze, keccakSqueezeBlocks, load64, makeHint, montgomeryReduce, ntt, packPk, packSig, packSk, polyAdd, polyCAddQ, polyChallenge, polyChkNorm, polyDecompose, polyEtaPack, polyEtaUnpack, polyInvNTTToMont, polyMakeHint, polyNTT, polyPointWiseMontgomery, polyPower2round, polyReduce, polyShiftL, polySub, polyT0Pack, polyT0Unpack, polyT1Pack, polyT1Unpack, polyUniform, polyUniformEta, polyUniformGamma1, polyUseHint, polyVecKAdd, polyVecKCAddQ, polyVecKChkNorm, polyVecKDecompose, polyVecKInvNTTToMont, polyVecKMakeHint, polyVecKNTT, polyVecKPackW1, polyVecKPointWisePolyMontgomery, polyVecKPower2round, polyVecKReduce, polyVecKShiftL, polyVecKSub, polyVecKUniformEta, polyVecKUseHint, polyVecLAdd, polyVecLChkNorm, polyVecLInvNTTToMont, polyVecLNTT, polyVecLPointWiseAccMontgomery, polyVecLPointWisePolyMontgomery, polyVecLReduce, polyVecLUniformEta, polyVecLUniformGamma1, polyVecMatrixExpand, polyVecMatrixPointWiseMontgomery, polyW1Pack, polyZPack, polyZUnpack, power2round, reduce32, rejEta, rejUniform, shake128Absorb, shake128AbsorbOnce, shake128Finalize, shake128Init, shake128Squeeze, shake128SqueezeBlocks, shake256Absorb, shake256Finalize, shake256Init, shake256SqueezeBlocks, store64, unpackPk, unpackSig, unpackSk, useHint, zetas };
