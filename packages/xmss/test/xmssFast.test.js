import { expect } from 'chai';
import { describe, it } from 'mocha';
import { newBDSState, newTreeHashInst, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import {
  XMSSFastGenKeyPair,
  bdsRound,
  bdsTreeHashUpdate,
  expandSeed,
  genChain,
  genLeafWOTS,
  getSeed,
  hashF,
  lTree,
  treeHashMinHeightOnStack,
  treeHashSetup,
  treeHashUpdate,
  wOTSPKGen,
  xmssFastUpdate,
} from '../src/xmssFast.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './utility/testUtility.js';

describe('Test cases for [xmssFast]', function testFunction() {
  this.timeout(0);

  describe('getSeed', () => {
    it('should update the seed variable with hashFunction SHA2_256', () => {
      const seed = getUInt8ArrayFromHex('0203050704090100');
      getSeed(
        HASH_FUNCTION.SHA2_256,
        seed,
        getUInt8ArrayFromHex('0205010904090100'),
        1,
        getUInt8ArrayFromHex('0300000000000208')
      );
      const expectedSeed = getUInt8ArrayFromHex('dcf95c61e21dd076');

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should update the seed variable with hashFunction SHAKE_128', () => {
      const seed = getUInt8ArrayFromHex('0203050704090100');
      getSeed(
        HASH_FUNCTION.SHAKE_128,
        seed,
        getUInt8ArrayFromHex('0205010904090100'),
        1,
        getUInt32ArrayFromHex('0000000300000000000000000000000000000000000000000000000200000008')
      );
      const expectedSeed = getUInt8ArrayFromHex('345bbd9e3a3c9a5f');

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should update the seed variable with hashFunction SHAKE_256', () => {
      const seed = getUInt8ArrayFromHex('0203050704090100');
      getSeed(
        HASH_FUNCTION.SHAKE_256,
        seed,
        getUInt8ArrayFromHex('0205010904090100'),
        1,
        getUInt32ArrayFromHex('0000000300000000000000000000000000000000000000000000000200000008')
      );
      const expectedSeed = getUInt8ArrayFromHex('1c58e2fec10caea7');

      expect(seed).to.deep.equal(expectedSeed);
    });
  });

  describe('expandSeed', () => {
    it('should expand the outseeds based on the inseeds provided', () => {
      const outSeeds = getUInt8ArrayFromHex('0305010207020703');
      const inSeeds = getUInt8ArrayFromHex('0902010304040302020703');
      const n = 2;
      const len = 3;
      const expectedOutSeeds = getUInt8ArrayFromHex('4adc67ce33d20703');
      const expectedInSeeds = getUInt8ArrayFromHex('0902010304040302020703');
      expandSeed(HASH_FUNCTION.SHAKE_256, outSeeds, inSeeds, n, len);

      expect(outSeeds).to.deep.equal(expectedOutSeeds);
      expect(inSeeds).to.deep.equal(expectedInSeeds);
    });
  });

  describe('hashF', () => {
    it('should set the result to the out variable, with SHAKE_128', () => {
      const out = getUInt8ArrayFromHex('0305010207020703');
      const input = getUInt8ArrayFromHex('010304040302020703');
      const pubSeed = getUInt8ArrayFromHex('090204050704040302020703');
      const addr = getUInt32ArrayFromHex('0000000700000004000000080000000200000006000000000000000200000005');
      const n = 2;
      const expectedOut = getUInt8ArrayFromHex('744ed2998f2ce23c');
      const expectedInput = getUInt8ArrayFromHex('010304040302020703');
      const expectedPubSeed = getUInt8ArrayFromHex('090204050704040302020703');
      const expectedAddr = getUInt32ArrayFromHex('0000000700000004000000080000000200000006000000000000000200000001');
      hashF(HASH_FUNCTION.SHAKE_128, out, input, pubSeed, addr, n);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should set the result to the out variable, with SHA2_256', () => {
      const out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000200000009');
      const n = 32;
      const expectedOut = getUInt8ArrayFromHex(
        '535b1a6f45bdd4796c7db5a811f111e6387f2f39a36f18c42fde67fbd4eff9ca030501020702070303050102070207030305010207020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000200000001');
      hashF(HASH_FUNCTION.SHA2_256, out, out, pubSeed, addr, n);

      expect(out).to.deep.equal(expectedOut);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('genChain', () => {
    it('should generate chain in the out variable, with SHA2_256 hashing', () => {
      const out = getUInt8ArrayFromHex(
        '0305010207020703030501020702070303050102070207030305010207020703030501020702070303050102070207030305010207020703'
      );
      const input = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedOut = getUInt8ArrayFromHex(
        'c57b9ace078f80a2c16d26b4c3adae9224ea50857c9946733a504c56c1bfdd33030501020702070303050102070207030305010207020703'
      );
      const expectedInput = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000400000001');
      genChain(HASH_FUNCTION.SHA2_256, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate chain in the out variable, with SHAKE_128 hashing', () => {
      const out = getUInt8ArrayFromHex(
        '0305010207020703030501020702070303050102070207030305010207020703030501020702070303050102070207030305010207020703'
      );
      const input = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedOut = getUInt8ArrayFromHex(
        '7e9ef0fe02cfa01c59077cd4f18473c0597a78376f6c270cf508c1267909b616581921a5ce1b4ed1bca8a9987b591c9cdddb8b9bbbd0bbe0'
      );
      const expectedInput = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000400000001');
      genChain(HASH_FUNCTION.SHAKE_128, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate chain in the out variable, with SHAKE_256 hashing', () => {
      const out = getUInt8ArrayFromHex(
        '0305010207020703030501020702070303050102070207030305010207020703030501020702070303050102070207030305010207020703'
      );
      const input = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedOut = getUInt8ArrayFromHex(
        '79923637c41f0a0c136d474e05a89eceee8c710682d51f4c0c904765e67243e3a98944526187afdd4615457c7824c6170f145aca4ebb6957'
      );
      const expectedInput = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000400000001');
      genChain(HASH_FUNCTION.SHAKE_256, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('wOTSPKGen', () => {
    it('should generate public key, with SHA2_256 hashing', () => {
      const pk = getUInt8ArrayFromHex(
        '04020204090004162137580b21060809020106090004162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b2106080902'
      );
      const sk = getUInt8ArrayFromHex('0403020303050102070207030305');
      const w = 5;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('08030106090002010305');
      const addr = getUInt32ArrayFromHex('000000160000002c000000050000000700000021000000070000000800000016');
      const expectedPk = getUInt8ArrayFromHex(
        '33220f9103d593369099b733786fd9fc741dab3b8126162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b2106080902'
      );
      const expectedSk = getUInt8ArrayFromHex('0403020303050102070207030305');
      const expectedPubSeed = getUInt8ArrayFromHex('08030106090002010305');
      const expectedAddr = getUInt32ArrayFromHex('000000160000002c0000000500000007000000210000000a0000000300000001');
      wOTSPKGen(HASH_FUNCTION.SHA2_256, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate public key, with SHAKE_128 hashing', () => {
      const pk = getUInt8ArrayFromHex(
        '030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const sk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const w = 6;
      const n = 3;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('060301050603');
      const addr = getUInt32ArrayFromHex('000000080000002c000000050000000700000021000000070000000800000016');
      const expectedPk = getUInt8ArrayFromHex(
        'f8db6aea6471ec2c820bdcadece3cc6f1d3168b1dd1bec8f7a8378bf4509d891626ab9525cd1877efd30319c19030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const expectedSk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const expectedPubSeed = getUInt8ArrayFromHex('060301050603');
      const expectedAddr = getUInt32ArrayFromHex('000000080000002c0000000500000007000000210000000e0000000400000001');
      wOTSPKGen(HASH_FUNCTION.SHAKE_128, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate public key, with SHAKE_256 hashing', () => {
      const pk = getUInt8ArrayFromHex(
        '030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const sk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const w = 16;
      const n = 7;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('04050301030202');
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedPk = getUInt8ArrayFromHex(
        'ce5d0c8fb9644567020aa13bbd60048c71a41b8e4070fa42f03c024c5c2ad51995502c467b9fc916212085cab85fdd3585c823c621ced9505b31c8a3d951bfac81f8eff90f9cecae95700e2c9898ab25f20495b146e99b4c2f86f3e7f23aceddd392637ff9101607bff292f235ec7bb60303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const expectedSk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const expectedPubSeed = getUInt8ArrayFromHex('04050301030202');
      const expectedAddr = getUInt32ArrayFromHex('00000004000000030000000200000002000000070000000f0000000e00000001');
      wOTSPKGen(HASH_FUNCTION.SHAKE_256, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('lTree', () => {
    it('should generate lTree, with SHA2_256 hashing', () => {
      const n = 2;
      const w = 256;
      const params = newWOTSParams(n, w);
      const leaf = getUInt8ArrayFromHex('214409022d4d050307090207090208020507214409022d4d1738184e63');
      const wotsPk = getUInt8ArrayFromHex(
        '38184e63214438184e6309022d4d1738184e63050307214409022d4d1738184e63214409022d4d1738184e63050307'
      );
      const pubSeed = getUInt8ArrayFromHex('050307090207090208020507214409022d4d1738184e63');
      const addr = getUInt8ArrayFromHex('0403020207030909');
      const expectedLeaf = getUInt8ArrayFromHex('697309022d4d050307090207090208020507214409022d4d1738184e63');
      const expectedWotsPk = getUInt8ArrayFromHex(
        '6973245e214438184e6309022d4d1738184e63050307214409022d4d1738184e63214409022d4d1738184e63050307'
      );
      const expectedPubSeed = getUInt8ArrayFromHex('050307090207090208020507214409022d4d1738184e63');
      const expectedAddr = getUInt8ArrayFromHex('0403020207020002');
      lTree(HASH_FUNCTION.SHA2_256, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate lTree, with SHAKE_128 hashing', () => {
      const n = 1;
      const w = 6;
      const params = newWOTSParams(n, w);
      const leaf = getUInt8ArrayFromHex('6304032d4d02060802090308164f02');
      const wotsPk = getUInt8ArrayFromHex(
        '3b022d4d1738184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const pubSeed = getUInt8ArrayFromHex('0507214409022d4d173818050307090207090208020507214409022d4d1738184e63');
      const addr = getUInt8ArrayFromHex('0920020703160909');
      const expectedLeaf = getUInt8ArrayFromHex('2e04032d4d02060802090308164f02');
      const expectedWotsPk = getUInt8ArrayFromHex(
        '2e6148181738184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '0507214409022d4d173818050307090207090208020507214409022d4d1738184e63'
      );
      const expectedAddr = getUInt8ArrayFromHex('0920020703030002');
      lTree(HASH_FUNCTION.SHAKE_128, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate lTree, with SHAKE_256 hashing', () => {
      const n = 1;
      const w = 6;
      const params = newWOTSParams(n, w);
      const leaf = getUInt8ArrayFromHex('060802090308166304032d4d024f02');
      const wotsPk = getUInt8ArrayFromHex(
        '4409022d4d1738184e3b022d4d1738184e6321630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const pubSeed = getUInt8ArrayFromHex('050307090207090208023707214409022d4d17381807214409022d4d1738184e63');
      const addr = getUInt8ArrayFromHex('2c0b060703160909');
      const expectedLeaf = getUInt8ArrayFromHex('070802090308166304032d4d024f02');
      const expectedWotsPk = getUInt8ArrayFromHex(
        '072970384d1738184e3b022d4d1738184e6321630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '050307090207090208023707214409022d4d17381807214409022d4d1738184e63'
      );
      const expectedAddr = getUInt8ArrayFromHex('2c0b060703030002');
      lTree(HASH_FUNCTION.SHAKE_256, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('genLeafWOTS', () => {
    it('should generate leafWOTS, with SHA2_256 hashing', () => {
      const leaf = getUInt8ArrayFromHex('030504070206010501020503020602070305010205030206');
      const skSeed = getUInt8ArrayFromHex('0305010501020503020602070305010205030206');
      const xmssParams = newXMSSParams(2, 2, 5, 2);
      const pubSeed = getUInt8ArrayFromHex('03050105010205030607020602070305010205030206');
      const lTreeAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000000700000003000000160000000900000009');
      const otsAddr = getUInt32ArrayFromHex('0000002c0000000b0000000600000007000000160000002c0000000900000009');
      const expectedLeaf = getUInt8ArrayFromHex('71af04070206010501020503020602070305010205030206');
      const expectedSkSeed = getUInt8ArrayFromHex('0305010501020503020602070305010205030206');
      const expectedPubSeed = getUInt8ArrayFromHex('03050105010205030607020602070305010205030206');
      const expectedLTreeAddr = getUInt32ArrayFromHex(
        '0000002c0000000b000000060000000700000003000000040000000000000002'
      );
      const expectedOtsAddr = getUInt32ArrayFromHex('0000002c0000000b0000000600000007000000160000000a0000000300000001');
      genLeafWOTS(HASH_FUNCTION.SHA2_256, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });

    it('should generate leafWOTS, with SHAKE_128 hashing', () => {
      const leaf = getUInt8ArrayFromHex('08030504070206010501020503020608020703050102050302');
      const skSeed = getUInt8ArrayFromHex('0903050105010205030206020703050102050302');
      const xmssParams = newXMSSParams(4, 3, 16, 9);
      const pubSeed = getUInt8ArrayFromHex('09050105010205030607020602070305010205030206');
      const lTreeAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000000700000025000000160000000900000009');
      const otsAddr = getUInt32ArrayFromHex('0000002c0000000b0000000600000007000000160000002c0000006300000009');
      const expectedLeaf = getUInt8ArrayFromHex('919bd67b070206010501020503020608020703050102050302');
      const expectedSkSeed = getUInt8ArrayFromHex('0903050105010205030206020703050102050302');
      const expectedPubSeed = getUInt8ArrayFromHex('09050105010205030607020602070305010205030206');
      const expectedLTreeAddr = getUInt32ArrayFromHex(
        '0000002c0000000b000000060000000700000025000000040000000000000002'
      );
      const expectedOtsAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000000700000016000000090000000e00000001');
      genLeafWOTS(HASH_FUNCTION.SHAKE_128, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });

    it('should generate leafWOTS, with SHAKE_256 hashing', () => {
      const leaf = getUInt8ArrayFromHex('04033807162c5629020608020703050102050302');
      const skSeed = getUInt8ArrayFromHex('09030501050102050302060207030501020503022c5629');
      const xmssParams = newXMSSParams(9, 7, 6, 5);
      const pubSeed = getUInt8ArrayFromHex('092c5629050105010205030607020602070305010205030206');
      const lTreeAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000004a00000025000000160000000900000009');
      const otsAddr = getUInt32ArrayFromHex('0000002c0000000b0000003f00000007000000160000002c0000006300000009');
      const expectedLeaf = getUInt8ArrayFromHex('1547a0264413f1a0560608020703050102050302');
      const expectedSkSeed = getUInt8ArrayFromHex('09030501050102050302060207030501020503022c5629');
      const expectedPubSeed = getUInt8ArrayFromHex('092c5629050105010205030607020602070305010205030206');
      const expectedLTreeAddr = getUInt32ArrayFromHex(
        '0000002c0000000b000000060000004a00000025000000060000000000000002'
      );
      const expectedOtsAddr = getUInt32ArrayFromHex('0000002c0000000b0000003f0000000700000016000000270000000400000001');
      genLeafWOTS(HASH_FUNCTION.SHAKE_256, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });
  });

  describe('treeHashSetup', () => {
    it('should setup tree hash, with SHA2_256 hashing', () => {
      const index = 5;
      const height = 3;
      const k = 3;
      const w = 7;
      const n = 3;
      const node = getUInt8ArrayFromHex('3807162c5629020608020703050102050302');
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('090734045629020608020703050102050302');
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('3807162c5629020608020703050102050336');
      const addr = getUInt32ArrayFromHex(
        '0000005800000007000000160000002c00000056000000290000000200000006000000020000000700000003000000050000000100000002000000050000000300000002'
      );
      const expectedNode = getUInt8ArrayFromHex('021f042c5629020608020703050102050302');
      const expectedSkSeed = getUInt8ArrayFromHex('090734045629020608020703050102050302');
      const expectedPubSeed = getUInt8ArrayFromHex('3807162c5629020608020703050102050336');
      const expectedAddr = getUInt32ArrayFromHex(
        '0000005800000007000000160000002c00000056000000290000000200000006000000020000000700000003000000050000000100000002000000050000000300000002'
      );
      treeHashSetup(HASH_FUNCTION.SHA2_256, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should setup tree hash, with SHAKE_128 hashing', () => {
      const index = 7;
      const height = 4;
      const k = 2;
      const w = 5;
      const n = 9;
      const node = getUInt8ArrayFromHex('0d0b0508050d0302060f0b080e0b0f0e');
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0710120b0c06130f0f060f010d11150108131106120510');
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('0903150d0d0b0e141719000011120b09060a0f0e070b0e0f0906');
      const addr = getUInt32ArrayFromHex(
        '0000000e000000070000000f0000000700000004000000070000000f0000000b000000070000000f00000004000000090000000b00000005000000040000000200000006'
      );
      const expectedNode = getUInt8ArrayFromHex('d2da2b4c7c54cb324c0f0b080e0b0f0e');
      const expectedSkSeed = getUInt8ArrayFromHex('0710120b0c06130f0f060f010d11150108131106120510');
      const expectedPubSeed = getUInt8ArrayFromHex('0903150d0d0b0e141719000011120b09060a0f0e070b0e0f0906');
      const expectedAddr = getUInt32ArrayFromHex(
        '0000000e000000070000000f0000000700000004000000070000000f0000000b000000070000000f00000004000000090000000b00000005000000040000000200000006'
      );
      treeHashSetup(HASH_FUNCTION.SHAKE_128, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should setup tree hash, with SHAKE_256 hashing', () => {
      const index = 12;
      const height = 7;
      const k = 4;
      const w = 256;
      const n = 3;
      const node = getUInt8ArrayFromHex('000d030a0b0c02090a080b0205050301');
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const xmssParams = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const addr = getUInt32ArrayFromHex(
        '0000000300000006000000000000000c000000040000000000000010000000020000001000000000000000050000000a0000000e0000000d0000000c0000000700000004'
      );
      const expectedNode = getUInt8ArrayFromHex('44b1920a0b0c02090a080b0205050301');
      const expectedSkSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const expectedPubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const expectedAddr = getUInt32ArrayFromHex(
        '0000000300000006000000000000000c000000040000000000000010000000020000001000000000000000050000000a0000000e0000000d0000000c0000000700000004'
      );
      treeHashSetup(HASH_FUNCTION.SHAKE_256, node, index, bdsState, skSeed, xmssParams, pubSeed, addr);

      expect(node).to.deep.equal(expectedNode);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('XMSSFastGenKeyPair', () => {
    it('should generate secret key and public key, with SHA2_256 hashing', () => {
      const height = 2;
      const k = 2;
      const w = 16;
      const n = 32;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = getUInt8ArrayFromHex(
        '27121318191e172a0e3c0c1f0d27300f393c071e2a281f36131200010f3802340c190e15383e0f0b130c31292024220f041c1d37002b012d230b17240a091c0f'
      );
      const sk = getUInt8ArrayFromHex(
        '7c48145a1b656c4b10742f042160813d723c7f0d082c1e606d2e30101f1958754711594f53717103010a722418715d36253416245a2b071e4e4c2754747d2a5b1a2e5b3d502e3a616f5149217566431661255f7f562e4e30512b1e367315306e2a102e4d0a6f510d5e4d7a0a5306275a42232d152a1708684302541569137507673f5366'
      );
      const seed = getUInt8ArrayFromHex(
        '102615201829042a1b2423140f0e091e0a202f2429250f1f0206190e1212231c231501201e041e15121f0b2d2d232101'
      );
      const expectedPk = getUInt8ArrayFromHex(
        '88a882c691b377578f2b3486c9bd0dd6393db5d7af7719a5df106c00d79797e28343e3b3cffb0dfc38f3ce6beff4dea6f363ecd3b4842d0bad2d73257b0f7b9e'
      );
      const expectedSk = getUInt8ArrayFromHex(
        '000000000252a9fc1fc1ff75ddd8ca34bc73201eac930121a400762c917ffd22c56054f00fb44853ff79c02f51aabeaa1d629e09ed20c3d59fbf552222d3e93110dbe0978343e3b3cffb0dfc38f3ce6beff4dea6f363ecd3b4842d0bad2d73257b0f7b9e88a882c691b377578f2b3486c9bd0dd6393db5d7af7719a5df106c00d79797e2'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '102615201829042a1b2423140f0e091e0a202f2429250f1f0206190e1212231c231501201e041e15121f0b2d2d232101'
      );
      XMSSFastGenKeyPair(HASH_FUNCTION.SHA2_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should generate secret key and public key, with SHAKE_128 hashing', () => {
      const height = 4;
      const k = 3;
      const w = 7;
      const n = 37;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = getUInt8ArrayFromHex(
        '311410342b1b323b151a1f113e2d07313615232226080a112038143d3e2f050b32101e06061a2209083c3f1c12313d2822391a2a111208061918140022123316'
      );
      const sk = getUInt8ArrayFromHex(
        '7f1f621e630a3f4f2f61231b39232f190d031f3d243e6f6e20100469387c1d654c2a767c4a2a33367055260f36835e1b21272b1e213e3e8331395f0552297a284e27020d5e3d7c804a64366e7a643f653e031724583b3d635c4a314d145f554e426e5c6d3e46052636814b07360e164f72421c2e0e503e5b5f666532735843325424481d'
      );
      const seed = getUInt8ArrayFromHex(
        '2723042729061f24221c2e18182a2f2321060a2e0e20011e072f1a1c09071f260c122b281c112701242d002b21180f11'
      );
      const expectedPk = getUInt8ArrayFromHex(
        'fa872a4f90a9a989e38b5aca522d3f26e8b7cb1f22bb7f376eb061d668ed570216d0d6278edbcdd5f805ce41274d0ca4b523de88b29aeb6296c2fb3e46052636'
      );
      const expectedSk = getUInt8ArrayFromHex(
        '00000000224f2d06b66f41867fab1930e619eb3544a29d806497c2f32a0fc8f1b9e81f557689eeb3b3db12a800320e5dd803ec7a9624e17d2f1a4aa3dac91ac9bc42eea570db23dffe10be09b9f6dbcdd5f805ce41274d0ca4b523de88b29aeb6296c2fb3e46052636814b07360e164f72421cfa872a4f90a9a989e38b5aca522d3f26e8'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '2723042729061f24221c2e18182a2f2321060a2e0e20011e072f1a1c09071f260c122b281c112701242d002b21180f11'
      );
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_128, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should generate secret key and public key, with SHAKE_256 hashing', () => {
      const height = 2;
      const k = 2;
      const w = 16;
      const n = 32;
      const xmssParams = newXMSSParams(n, height, w, k);
      const bdsState = newBDSState(height, n, k);
      const pk = new Uint8Array(64);
      const sk = new Uint8Array(132);
      const seed = getUInt8ArrayFromHex(
        '030501020503020602070305010205030206020703050102050302060207030501020503020602070305010205030206'
      );
      const expectedPk = getUInt8ArrayFromHex(
        '693e356d62a84c53f5162f36801f19b445f5876b70ad3c16a828991ecf9edd8225bfa7c0458254b18322dc4730d2d2028d17536a26c958967fea723371019f13'
      );
      const expectedSk = getUInt8ArrayFromHex(
        '0000000013f324641ae9b1aef4b11890dd7918a2e7fd3d8331e33df9b0a764dfe3b0473d956f4bce2ccb5de9484a7e2cf0687db073f51de3836b86fc2fc8eda92390380f25bfa7c0458254b18322dc4730d2d2028d17536a26c958967fea723371019f13693e356d62a84c53f5162f36801f19b445f5876b70ad3c16a828991ecf9edd82'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '030501020503020602070305010205030206020703050102050302060207030501020503020602070305010205030206'
      );
      XMSSFastGenKeyPair(HASH_FUNCTION.SHAKE_256, xmssParams, pk, sk, bdsState, seed);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(seed).to.deep.equal(expectedSeed);
    });
  });

  describe('treeHashUpdate', () => {
    it('should update tree hash, with SHA2_256 hashing', () => {
      const height = 5;
      const k = 3;
      const w = 256;
      const n = 4;
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const addr = getUInt32ArrayFromHex('0000000300000006000000000000000c00000004000000000000000400000005');
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = getUInt8ArrayFromHex('990b9713');
      const expectedSkSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const expectedPubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const expectedAddr = getUInt32ArrayFromHex('0000000300000006000000000000000c00000004000000000000000400000005');
      treeHashUpdate(HASH_FUNCTION.SHA2_256, bdsState.treeHash[0], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[0]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should update tree hash, with SHAKE_128 hashing', () => {
      const height = 7;
      const k = 3;
      const w = 7;
      const n = 4;
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0d09080f1211170704061d1d011810081f16110a120a13090c0c0f1f021b1a01');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('0f150c0113140a01110a0f040b021010120c081108050709');
      const addr = getUInt32ArrayFromHex('0000001e0000000d0000001900000000000000680000002c0000005f0000006e');
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = getUInt8ArrayFromHex('4535a877');
      const expectedSkSeed = getUInt8ArrayFromHex('0d09080f1211170704061d1d011810081f16110a120a13090c0c0f1f021b1a01');
      const expectedPubSeed = getUInt8ArrayFromHex('0f150c0113140a01110a0f040b021010120c081108050709');
      const expectedAddr = getUInt32ArrayFromHex('0000001e0000000d0000001900000000000000680000002c0000005f0000006e');
      treeHashUpdate(HASH_FUNCTION.SHAKE_128, bdsState.treeHash[2], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[2]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should update tree hash, with SHAKE_256 hashing', () => {
      const height = 9;
      const k = 5;
      const w = 16;
      const n = 5;
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('1d523a6f1713482b001e7b6e4f39543a581b0a776403647b30480f70114e275504112816');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex(
        '30116f414c37325d415f6429637849126e5147083e2d0a2f062110186074395d39341615530a2a2f101f67106b77711428182a245a362c77041574225b7440'
      );
      const addr = getUInt32ArrayFromHex('000000700000003e000000100000004000000004000000190000007b00000010');
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = getUInt8ArrayFromHex('e004bd38ea');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '1d523a6f1713482b001e7b6e4f39543a581b0a776403647b30480f70114e275504112816'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '30116f414c37325d415f6429637849126e5147083e2d0a2f062110186074395d39341615530a2a2f101f67106b77711428182a245a362c77041574225b7440'
      );
      const expectedAddr = getUInt32ArrayFromHex('000000700000003e000000100000004000000004000000190000007b00000010');
      treeHashUpdate(HASH_FUNCTION.SHAKE_256, bdsState.treeHash[3], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[3]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('treeHashMinHeightOnStack', () => {
    it('should update r with stackOffset[0] and modified values', () => {
      const height = 9;
      const k = 5;
      const w = 6;
      const n = 5;
      const state = newBDSState(height, n, k);
      const params = newXMSSParams(n, height, w, k);
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(9);
    });

    it('should update r with stackOffset[6] and modified values', () => {
      const height = 11;
      const k = 4;
      const w = 16;
      const n = 3;
      const params = newXMSSParams(n, height, w, k);
      const state = newBDSState(height, n, k);
      state.stackOffset = 6;
      state.treeHash[0].stackUsage = 4;
      state.stackLevels = getUInt8ArrayFromHex('212d02044d1702');
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(2);
    });

    it('should update r with stackOffset[17] and modified values', () => {
      const height = 5;
      const k = 1;
      const w = 256;
      const n = 2;
      const params = newXMSSParams(n, height, w, k);
      const state = newBDSState(height, n, k);
      state.stackOffset = 17;
      state.treeHash[0].stackUsage = 12;
      state.stackLevels = getUInt8ArrayFromHex('4202054d08066300014202054d08066300014202054d0806630001');
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(0);
    });
  });

  describe('bdsTreeHashUpdate', () => {
    it('should update the tree hash, with SHA2_256 hashing', () => {
      const height = 5;
      const k = 1;
      const w = 16;
      const n = 1;
      const bdsState = newBDSState(height, n, k);
      const updates = 7;
      const skSeed = getUInt8ArrayFromHex(
        '30037231306c3b1c5f466a45103b436049194a6b1044164d2f16384813114006303b505436602f051e7516'
      );
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('62302c3c112863384440293142465c045c1e5c3f69220f53781718524a7a34465109272f');
      const addr = getUInt32ArrayFromHex('0000001f00000006000000130000005700000078000000290000000d0000003e');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '30037231306c3b1c5f466a45103b436049194a6b1044164d2f16384813114006303b505436602f051e7516'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '62302c3c112863384440293142465c045c1e5c3f69220f53781718524a7a34465109272f'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000001f00000006000000130000005700000078000000290000000d0000003e');
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHA2_256, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(3);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should update the tree hash, with SHAKE_128 hashing', () => {
      const height = 11;
      const k = 4;
      const w = 7;
      const n = 3;
      const bdsState = newBDSState(height, n, k);
      const updates = 9;
      const skSeed = getUInt8ArrayFromHex('13797a694f423f2e074651744426630b016f71690313012d7252155c312228283460327727');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('455600620f264b675f08016b584760743c1e354f2d29343b344b1f27');
      const addr = getUInt32ArrayFromHex('00000042000000250000000900000028000000780000000c0000002d0000004b');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '13797a694f423f2e074651744426630b016f71690313012d7252155c312228283460327727'
      );
      const expectedPubSeed = getUInt8ArrayFromHex('455600620f264b675f08016b584760743c1e354f2d29343b344b1f27');
      const expectedAddr = getUInt32ArrayFromHex('00000042000000250000000900000028000000780000000c0000002d0000004b');
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHAKE_128, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(2);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should update the tree hash, with SHAKE_256 hashing', () => {
      const height = 17;
      const k = 13;
      const w = 256;
      const n = 7;
      const bdsState = newBDSState(height, n, k);
      const updates = 17;
      const skSeed = getUInt8ArrayFromHex('360d385c002a5f4647673c734f3112303c646a70');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex(
        '78333c58232b4e4601370e5d5151334265192b0e3a1e17786b252f1e5d421c36503b4276512e32'
      );
      const addr = getUInt32ArrayFromHex('0000007300000029000000450000006600000014000000260000005e00000021');
      const expectedSkSeed = getUInt8ArrayFromHex('360d385c002a5f4647673c734f3112303c646a70');
      const expectedPubSeed = getUInt8ArrayFromHex(
        '78333c58232b4e4601370e5d5151334265192b0e3a1e17786b252f1e5d421c36503b4276512e32'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000007300000029000000450000006600000014000000260000005e00000021');
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHAKE_256, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(13);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });
  });

  describe('bdsRound', () => {
    it('should run bdsRound, with SHA2_256 hashing', () => {
      const height = 19;
      const k = 7;
      const w = 16;
      const n = 17;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 5;
      const skSeed = getUInt8ArrayFromHex('46530f313934423f410c2817657471590c33346b0569645f61026364071a57');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('68150237604a400a380f16751c492c54653671064b45311c19712d');
      const addr = getUInt32ArrayFromHex('0000005a0000001800000002000000060000005a0000003b0000000d00000051');
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.treeHash[0].nextIdx = 9;
      expectedBdsState.auth = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000092ad0ca473824bce7fb6b9a73a8653e1f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const expectedSkSeed = getUInt8ArrayFromHex('46530f313934423f410c2817657471590c33346b0569645f61026364071a57');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = getUInt8ArrayFromHex('68150237604a400a380f16751c492c54653671064b45311c19712d');
      const expectedAddr = getUInt32ArrayFromHex('0000005a0000001800000002000000060000005a0000003b0000000d00000051');
      bdsRound(HASH_FUNCTION.SHA2_256, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should run bdsRound, with SHAKE_128 hashing', () => {
      const height = 8;
      const k = 8;
      const w = 19;
      const n = 3;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 13;
      const skSeed = getUInt8ArrayFromHex(
        '633d6e346a023c1d203d182b6f762850140b57071c45764b3e356a744f12665d1a531f0165145c4d0b065e601a47'
      );
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('643b767a1738271b254a680f753f773b5253546f0d6129510d321035716568191d17');
      const addr = getUInt32ArrayFromHex('00000072000000150000001b0000000f00000032000000150000001c00000007');
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex('000000551f69000000000000000000000000000000000000');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '633d6e346a023c1d203d182b6f762850140b57071c45764b3e356a744f12665d1a531f0165145c4d0b065e601a47'
      );
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = getUInt8ArrayFromHex(
        '643b767a1738271b254a680f753f773b5253546f0d6129510d321035716568191d17'
      );
      const expectedAddr = getUInt32ArrayFromHex('00000072000000150000001b0000000f00000032000000150000001c00000007');
      bdsRound(HASH_FUNCTION.SHAKE_128, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should run bdsRound, with SHAKE_256 hashing', () => {
      const height = 7;
      const k = 7;
      const w = 5;
      const n = 2;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 9;
      const skSeed = getUInt8ArrayFromHex(
        '29550a39602b527b143c1905000f3945061b392b182b6664140e05401f487806085c5f782149552439445e'
      );
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('582b480075135449342214041818320b7711270f422d51264766');
      const addr = getUInt32ArrayFromHex('0000005600000052000000170000001f00000024000000730000002500000046');
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex('0000087a00000000000000000000');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '29550a39602b527b143c1905000f3945061b392b182b6664140e05401f487806085c5f782149552439445e'
      );
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = getUInt8ArrayFromHex('582b480075135449342214041818320b7711270f422d51264766');
      const expectedAddr = getUInt32ArrayFromHex('0000005600000052000000170000001f00000024000000730000002500000046');
      bdsRound(HASH_FUNCTION.SHAKE_256, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });
  });

  describe('xmssFastUpdate', () => {
    it('should run xmssFastUpdate, with SHA2_256 hashing', () => {
      const height = 3;
      const k = 3;
      const w = 7;
      const n = 32;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '000000062e714e38484b246b2a6a5c3c27520e0503491a5f5d650236771415305b523c37521b6d3952365247371b385a5e7a1843263d475833382b041968451d6b68771378186a3776627479003e461a78362e38593f6006703d744557293f5464405429'
      );
      const bdsState = newBDSState(height, n, k);
      const newIdx = 7;
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '000000072e714e38484b246b2a6a5c3c27520e0503491a5f5d650236771415305b523c37521b6d3952365247371b385a5e7a1843263d475833382b041968451d6b68771378186a3776627479003e461a78362e38593f6006703d744557293f5464405429'
      );
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex(
        '31d5eb752ecca048fae65f9dbeb0896e07d901287847138d5cfcd0115aadc2fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      xmssFastUpdate(HASH_FUNCTION.SHA2_256, params, sk, bdsState, newIdx);

      expect(params).to.be.deep.equal(expectedParams);
      expect(sk).to.be.deep.equal(expectedSk);
      expect(bdsState).to.be.deep.equal(expectedBdsState);
    });

    it('should run xmssFastUpdate, with SHAKE_128 hashing', () => {
      const height = 4;
      const k = 4;
      const w = 256;
      const n = 46;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '00000003677a721e3a04384e44477a0b436111753672271d74762f50404f1f74174f234a454c640020315f11713d4311407b51094d010c345d27625b3d432742685e703e094b550a5b110626316443746858790f4b130b552f2851630b235e30475d316e4f18046b1f280b3f043c4729321f2e5d5918066a'
      );
      const bdsState = newBDSState(height, n, k);
      const newIdx = 12;
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '0000000c677a721e3a04384e44477a0b436111753672271d74762f50404f1f74174f234a454c640020315f11713d4311407b51094d010c345d27625b3d432742685e703e094b550a5b110626316443746858790f4b130b552f2851630b235e30475d316e4f18046b1f280b3f043c4729321f2e5d5918066a'
      );
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex(
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034c560df07bcd2dc0992269703659365ac2a70296f579f689868eea30a0d8887f2b06b3334ec168524e98828447ef923fa403e1b21cdc265b1ef8ba76a13372eabfec89ae63dedb0ba21042ba8eac717f436a1e232b97764d4a222c4'
      );
      xmssFastUpdate(HASH_FUNCTION.SHAKE_128, params, sk, bdsState, newIdx);

      expect(params).to.be.deep.equal(expectedParams);
      expect(sk).to.be.deep.equal(expectedSk);
      expect(bdsState).to.be.deep.equal(expectedBdsState);
    });

    it('should run xmssFastUpdate, with SHAKE_256 hashing', () => {
      const height = 5;
      const k = 2;
      const w = 7;
      const n = 43;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '000000080406090301070b0b0704000304050e040208080d0b0b02080f05060c06030c030e0c0c060e020203010d0a030507010d0401090a0d0e0d0c010b0a00060904040a020c090b060a0701010f0b05020d040e000505070b0c020b0a0b0e00040b0d0208070c'
      );
      const bdsState = newBDSState(height, n, k);
      const newIdx = 11;
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '0000000b0406090301070b0b0704000304050e040208080d0b0b02080f05060c06030c030e0c0c060e020203010d0a030507010d0401090a0d0e0d0c010b0a00060904040a020c090b060a0701010f0b05020d040e000505070b0c020b0a0b0e00040b0d0208070c'
      );
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex(
        'c8f4327cc03b65d517bd4d0945db33474f79ddfe07b769ae3415fbf488e8aa498940b11e3a77ffa48d418bc4151dbce1b14e56fb48efa9c6a8277a095f43a4ca1c26ace56d1ab88de3107fb95dd51fc4c1d749637492000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      expectedBdsState.treeHash[0].nextIdx = 13;
      expectedBdsState.treeHash[0].completed = 1;
      expectedBdsState.treeHash[0].node = getUInt8ArrayFromHex(
        '8e795933de848defcb66def8d6a3c646eb32e64ccaf4ed0a010d48d30ea35803b255bcd1800f5198e8b3f6'
      );
      expectedBdsState.treeHash[1].completed = 1;
      expectedBdsState.treeHash[1].node = getUInt8ArrayFromHex(
        '843684e0b72a9284721495e5dc6ea2a6664360b0f7bf6f0164b298d63861933a5c68a9c497e9cf87d79d9c'
      );
      xmssFastUpdate(HASH_FUNCTION.SHAKE_256, params, sk, bdsState, newIdx);

      expect(params).to.be.deep.equal(expectedParams);
      expect(sk).to.be.deep.equal(expectedSk);
      expect(bdsState).to.be.deep.equal(expectedBdsState);
    });
  });
});
