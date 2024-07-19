import { expect } from 'chai';
import { describe } from 'mocha';
import {
  newBDSState,
  newQRLDescriptor,
  newQRLDescriptorFromExtendedPk,
  newQRLDescriptorFromExtendedSeed,
  newWOTSParams,
  newXMSSParams,
} from '../src/classes.js';
import { COMMON, CONSTANTS, HASH_FUNCTION } from '../src/constants.js';
import {
  calcBaseW,
  calculateSignatureBaseSize,
  getHeightFromSigSize,
  getSignatureSize,
  getXMSSAddressFromPK,
  hMsg,
  initializeTree,
  isValidXMSSAddress,
  newXMSS,
  newXMSSFromExtendedSeed,
  newXMSSFromHeight,
  newXMSSFromSeed,
  validateAuthPath,
  verify,
  verifyWithCustomWOTSParamW,
  wotsPKFromSig,
  wotsSign,
  xmssFastSignMessage,
  xmssVerifySig,
} from '../src/xmss.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './utility/testUtility.js';

describe('Test cases for [xmss]', function testFunction() {
  this.timeout(0);

  describe('calculateSignatureBaseSize', () => {
    it('should return the signature base size for the keysize 65', () => {
      const [keySize] = getUInt32ArrayFromHex('00000041');
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 101;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });

    it('should return the signature base size for the keysize 399', () => {
      const [keySize] = getUInt32ArrayFromHex('0000018f');
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 435;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });

    it('should return the signature base size for the keysize 1064', () => {
      const [keySize] = getUInt32ArrayFromHex('00000428');
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 1100;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });
  });

  describe('getSignatureSize', () => {
    it('should return the signature size for the n[2] h[4] w[6] k[8]', () => {
      const n = 2;
      const h = 4;
      const w = 6;
      const k = 8;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 186;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });

    it('should return the signature size for the n[13] h[7] w[16] k[3]', () => {
      const n = 13;
      const h = 7;
      const w = 16;
      const k = 9;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 637;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });

    it('should return the signature size for the n[25] h[13] w[256] k[9]', () => {
      const n = 25;
      const h = 13;
      const w = 256;
      const k = 9;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 1127;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });
  });

  describe('hMsg', () => {
    it('should return an error if key length is not equal to 3 times n', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const out = getUInt8ArrayFromHex('22380207082d');
      const input = getUInt8ArrayFromHex('202d0708170507');
      const key = getUInt8ArrayFromHex('22380207082d22380202');
      const n = 3;
      const error = hMsg(hashFunction, out, input, key, n);

      expect(error).to.deep.equal({
        error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.`,
      });
    });

    it('should return an null error if the function is executed correctly', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const out = getUInt8ArrayFromHex('22380207082d');
      const input = getUInt8ArrayFromHex('202d0708170507');
      const key = getUInt8ArrayFromHex('22380207082d223802');
      const n = 3;
      const error = hMsg(hashFunction, out, input, key, n);

      expect(error).to.deep.equal({
        error: null,
      });
    });
  });

  describe('calcBaseW', () => {
    it('should calculate the base w, with w[6] input[4a4a...]', () => {
      const n = 13;
      const w = 6;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = getUInt8ArrayFromHex('4a4a20100cbd6e27a915b86f3b9e84fbcde1592d75515c8f52aaee9c4b');
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = getUInt8ArrayFromHex(
        '010400000104000000000000000104000000010400010505010401040000010500000001000105050001040001040105000104010000000000'
      );
      const expectedInput = getUInt8ArrayFromHex('4a4a20100cbd6e27a915b86f3b9e84fbcde1592d75515c8f52aaee9c4b');
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });

    it('should calculate the base w, with w[16] input[2217...]', () => {
      const n = 25;
      const w = 16;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = getUInt8ArrayFromHex('221742170407081722174217040708172217421704070817221742170407081722');
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = getUInt8ArrayFromHex(
        '0202010704020107000400070008010702020107040201070004000700080107020201070402010700040007000801070202000000'
      );
      const expectedInput = getUInt8ArrayFromHex('221742170407081722174217040708172217421704070817221742170407081722');
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });

    it('should calculate the base w, with w[256] input[9fca...]', () => {
      const n = 11;
      const w = 256;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = getUInt8ArrayFromHex('9fcad354487714f057dd96f113321010d43d23cc59a3e4d40aad2c92295f8348');
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = getUInt8ArrayFromHex('9fcad354487714f057dd960000');
      const expectedInput = getUInt8ArrayFromHex('9fcad354487714f057dd96f113321010d43d23cc59a3e4d40aad2c92295f8348');
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });
  });

  describe('wotsSign', () => {
    it('should throw an error if the size of addr is invalid', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const sig = getUInt8ArrayFromHex('e0c9f68aa304ec65958dc6c83498dd3307a5cd174282998b9ea495f1');
      const msg = getUInt8ArrayFromHex('8bac962de7f4e8b257424499c12b8f9faefc620cc4dd6b7a61ae');
      const sk = getUInt8ArrayFromHex('44ac8c8d2928fc2c76c5b568355fd9ba772483ce39');
      const n = 2;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('e80ad1787ef276fda4d00f46286f8eef9a7b60bdb0ca03d594ed26f195ee151a0a');
      const addr = getUInt8ArrayFromHex('883fd671d62de1');

      expect(() => wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr)).to.throw(
        'addr should be an array of size 8'
      );
    });

    it('should sign wots, with SHA2_256 n[2] w[16]', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const sig = getUInt8ArrayFromHex('e0c9f68aa304ec65958dc6c83498dd3307a5cd174282998b9ea495f1');
      const msg = getUInt8ArrayFromHex('8bac962de7f4e8b257424499c12b8f9faefc620cc4dd6b7a61ae');
      const sk = getUInt8ArrayFromHex('44ac8c8d2928fc2c76c5b568355fd9ba772483ce39');
      const n = 2;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('e80ad1787ef276fda4d00f46286f8eef9a7b60bdb0ca03d594ed26f195ee151a0a');
      const addr = getUInt8ArrayFromHex('88f33fd671d62de1');
      const expectedSig = getUInt8ArrayFromHex('428fad3327fb17f987df25883498dd3307a5cd174282998b9ea495f1');
      const expectedMsg = getUInt8ArrayFromHex('8bac962de7f4e8b257424499c12b8f9faefc620cc4dd6b7a61ae');
      const expectedSk = getUInt8ArrayFromHex('44ac8c8d2928fc2c76c5b568355fd9ba772483ce39');
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex(
        'e80ad1787ef276fda4d00f46286f8eef9a7b60bdb0ca03d594ed26f195ee151a0a'
      );
      const expectedAddr = getUInt8ArrayFromHex('88f33fd671050b01');
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should sign wots, with SHAKE_128 n[2] w[6]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const sig = getUInt8ArrayFromHex('0808020d040e000505070b0c020b0a0b0e00040b0d0208070c097a1a31b20f48e4');
      const msg = getUInt8ArrayFromHex('b268b014fdebd6097a1a31b20f48e4e2093869285dbd9b1702');
      const sk = getUInt8ArrayFromHex('723645967f189a4acbc6658a1ae9a089e0026c4b8da6efac');
      const n = 2;
      const w = 6;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('d92bc3e4eb84ef64bad2fc17002fb3ce967363311abb8086656ef64d2045e0a6ab82');
      const addr = getUInt8ArrayFromHex('fdd7cf90409b661f');
      const expectedSig = getUInt8ArrayFromHex('e6d5d72c3a90e8f7392286c5658dabd92b0e64f2765c08070c097a1a31b20f48e4');
      const expectedMsg = getUInt8ArrayFromHex('b268b014fdebd6097a1a31b20f48e4e2093869285dbd9b1702');
      const expectedSk = getUInt8ArrayFromHex('723645967f189a4acbc6658a1ae9a089e0026c4b8da6efac');
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex(
        'd92bc3e4eb84ef64bad2fc17002fb3ce967363311abb8086656ef64d2045e0a6ab82'
      );
      const expectedAddr = getUInt8ArrayFromHex('fdd7cf90400a0301');
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should sign wots, with SHAKE_256 n[3] w[256]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const sig = getUInt8ArrayFromHex('5e290e7a1b1a670de199a4ec954bfd3b72aca3e6a1954c09e7f08d');
      const msg = getUInt8ArrayFromHex('227a5312705cd86531b825773e71df32a24a4317f567b8821b9c99c420304182cf40e2');
      const sk = getUInt8ArrayFromHex('0bc66b3b21b295151d9e1f9afbdc43d51f1d8cb87a59f08481b6768c9b3b');
      const n = 3;
      const w = 256;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('f0a9a5450914063f8454a81a4c3f3ddcccf029fcc5e107f6b9');
      const addr = getUInt8ArrayFromHex('0dd7426a623769b7');
      const expectedSig = getUInt8ArrayFromHex('a3d28fd861260b43f56352ef0fd1e63b72aca3e6a1954c09e7f08d');
      const expectedMsg = getUInt8ArrayFromHex(
        '227a5312705cd86531b825773e71df32a24a4317f567b8821b9c99c420304182cf40e2'
      );
      const expectedSk = getUInt8ArrayFromHex('0bc66b3b21b295151d9e1f9afbdc43d51f1d8cb87a59f08481b6768c9b3b');
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex('f0a9a5450914063f8454a81a4c3f3ddcccf029fcc5e107f6b9');
      const expectedAddr = getUInt8ArrayFromHex('0dd7426a62040d01');
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('xmssFastSignMessage', () => {
    it('should return sigMsg after signing the message, with message[743e...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const n = 32;
      const height = 4;
      const w = 16;
      const k = 2;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        'afa43eed4f4c08562bb46aa85f8b7abbc693d3d78b981aaa7cde1e2a8801b199911ae58774b628a681e6352ad24f42dade1a3a2cf4dca45ad6830711e7eeb9a2294b47b8ac37c330db4b47193a9845128979b423f2de40d9373e74d6b83a9dd4f5c667f692633c0230af7b2027a8d20abbe624ace702eb1cbf083d92f30e50fad89f2b2d'
      );
      const bdsState = newBDSState(height, n, k);
      const message = getUInt8ArrayFromHex('743e154f026c55f859e45c937a56ae12b7f1f230a4fa3e9502cd8dae81b09b00');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        'afa43eee4f4c08562bb46aa85f8b7abbc693d3d78b981aaa7cde1e2a8801b199911ae58774b628a681e6352ad24f42dade1a3a2cf4dca45ad6830711e7eeb9a2294b47b8ac37c330db4b47193a9845128979b423f2de40d9373e74d6b83a9dd4f5c667f692633c0230af7b2027a8d20abbe624ace702eb1cbf083d92f30e50fad89f2b2d'
      );
      const expectedBdsState = {
        auth: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        nextLeaf: 0,
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        stackOffset: 0,
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
      };
      const expectedMessage = getUInt8ArrayFromHex('743e154f026c55f859e45c937a56ae12b7f1f230a4fa3e9502cd8dae81b09b00');
      const expectedSigMsg = getUInt8ArrayFromHex(
        'afa43eed38355fc6d0e06c48c3c82671b0c01136cf98a965d9d813c16e35a29a02f239369e00fdd64a0a14f8e9591d8c544261a20044553d80c9384d98ce5a68daff6c55a11d1b1a8597fc41d860f8b96a770c4addf26845aad44953289370ab8b7bc7c32bd16f6accb0fb1715bb84c6cf35c10d438a2f51f5b6918099cff9c73256bbef15dbb229fe6cbe8a192f387bb4cbd5755824177fff9d3c16a493f99e3b2eab5d10b2b75dd5eea5d289427910633ad1625fc3dbc1a51a723c5cfe8488ee909764ada9f07539702e3dcfd72e7d2b4afcea1bfdca3cf93d11e7b9feec49bbe655cc181309a783710f12d8c8492370dfcc0cbf6e8c98be4340c7d1b528d478253eb01349788c8a6ff7242927544c683f0d883be3c23503466077b7a80330529f416cb0a274f636be4555bfc913dfec7324ee95dfae22b94447a22d9e9a98d2c3ba1d0b974a5884707cb2392270645515d7c2cff029bf46cecd5d5a81978553d93d35fe70a2f7a14331686658122fe3adbb40558d8ccee49a53485167ed16363c856ddb71c28a9893eca7b41e0be179f2ee874d78d7cd31b48650e0df3f4b3d0723a48eaa2f7b5c771811ae08969164cbe31d7bfad30cb4a1c69f687d3243adf2effdfe8155d30f688ace6fc456d3eee90c5728a36a31cf60198c7d187ff8f55c205ae901553ad3234347cdb65c712dfcea8e76241d7d7b87a0d53cdc0a26a0a2f65182b6b289ec1b103dcf1da0589aa386a5097904761bc45ddcb62d4f70f4df17e4a5084999d12fd210d3a6c9f7be335f36fa6f83ca346f60b81ba266b04a0c1f95a418c0adae2245513d9ae13773fff2fc8343069fbd1bcfdc2e5778a81f2f0eaafc96bb9584c644a9f9a95647d161c62385f6262364fa8252557b75a157241ad85a8aff2555ba760047fcf7345b09bc03477abb952f7ca6873187c4663f24dcd54d973ae331de1188f416bee62f299389c38cb8df2e92882f153b812c607bb81bf4d8b4ce054d8a2771629227114455962777f26289b8fa8e3c38f800c26cb85e5605e1702ca0a9803a5941613c96051c78119a4fbcb954f8e63a524548dbed147f18567617712ed0b27958af7ecb1b2cfe105276525deb73cd8ab9b2043ad0c84ade85bb7065f3b9bdc13009bb7ae078eb85aacdd016063eef34687df2b11b59e598870054368da4fd61efe07a46f77c4b8c35f8928c8580c9998963fe0469909e90abdc654709579aeaee0687e1c99647faad5b845138de9aa9eee98f2058e33a5b351be2c7b78c2667e6d6d728ed01719a4a401dd5a963fbdfad50a6f80bd14d85abb77f0dd44b728ff0739c23e9212286e7bc5ff5610965a6bb1767ff90634a8df74e4de4dc0e677a0ef16dfdc64970cffdb1b83e792d661d478350437d1b357d8ba0158669cdfdacf680a989c0674dc846bb4f1284d7801e95b60b1801d10f9c8300f4b39f86ed4eedc3713c7ae975ed411b2200ea6bba357ed1ea1098fe9b14476b42d0def85b93266386a2060d46be72478822a8153290e944b92bafb0f6b1ccc86125128d5f26ba6eee0efeba6f84290ef2de889f3314dfe7d029a38b3e8aa52f517bfd865a4264533fc0bc6138d40b491cc4b0c8afb3d86d1d1c0064d876760dd75de752f799787f7acdf20364e00b9704fcf248d2eed96b77e3760dd5211eae89aa9a398ea54a85b0682838794ac5a7a4d500c209f64913177b0fe99947c0270a99ad3012eb21b3151859a7dea8f16b2404358e3c4971ac8583ee674e5c33697ef2dce93675e8a030ea467ea8623e96ba6897f03b1061e9c78a9e451bc75f1d79a2625a265bf5f72b7e493b58b2ed32be19ba1ff091b06e54205823a12270c93ac09a6d8ae96a13f6ed578b1064415576e0f5db9a3ae45f742203a383fd075d0466c4a0a58739d3b41f9e5a7ebb6b090097c4baf7cf9ec60204c5a6647015da8c9c4b70723349e4caf99469af7a3dadc6119cfa9ba2e86c946fd38b0838b6aa6e3c2c903c55df2c362461197678da9520a00a6be4f739d6d58edc94d360e9a4749fcb42cc76780479449f21a0a0b840cc9045dc80cf41d00dcdb8d67920cec451ba2a008f8996cfedd225f949f623334bcf51279089d0f1710786e0dbe75c79ff17c3e950867233046dee960781c7ce35e8e1c38b886b6227d8eed9903e0fe211c5f07e030c9d1bc15777eaa266ed02f170cc9910bbe8479909edee4c8ea62f70d03e324447d0ccd44ab465289154e2012897db46c307f6490f3a59e91b008906135d6b1769ad0f3c77aae4a7134f83ce0fca6057ca8e9765c5788ea400559ba4cf8fa5e7bca907f4bee952b75aaf5503a01474bad2c03dcc8bef199063a893b6daf9d354de92556fde23f69867d9b8573e2b746a9ce0691889bd1a5e9cdc487221161eab4c57babd24b0267ddbbd33ab1e1fbc7438da27038d72ab46b084b21865bb79b57891bf404bdd3e2cd51e629e3aa078b618262e6974e12c123775dd6fde9a0c739669902ef4a4ab465fd815a10ef4998bad21faf325cbbf322bff1fedae4c03f8b8d92bace8d2a6740692a76a03941e99550c82c95018c2b439d191360230a564467272e40410c1eb0c0102d07e6e6ea6e20e862b1f12e38891d0232de9389a486220e6b442bafe55591b36cbf6614ba291fa17b7e0f5fe77fb4a51b00b4de2d9be34b33e5ae280fe7eb428d7a38f6e3af6c74a23fcc218e29f311098e35d5b8385cb261a19b5bde227b9943867a967236b4b7376e78f9dfe3d5c5618b28c1012c144a1bc079650a4fd2d82ae25cef2594d3063d2c55fdf50aa8e64f7c805053a279e1687a27c338d5adf1e38092825cb0afc9b97906f4663b934b4fcaf9731c9d7f971a5c77593c24396b8f60098c45774eb4e3dc254fb9dbcca79230598deef356d7eef4265af9886c0ce8fdb6d8d7ed0e4c297fb76d2da82b1e2755da3beda0ca4c87fa276e20edda048e85d2ea42ecfc0c5a9c3724a5c0d4e55bb440e942585786d0f54fa232cb636ae7274a25e8f61272ea270e8d9428a90249ff62eecf822137ad014796d32302c496edad5e555e398fb44c9721c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const { sigMsg, error } = xmssFastSignMessage(hashFunction, params, sk, bdsState, message);

      expect(params).to.deep.equal(expectedParams);
      expect(sk).to.deep.equal(expectedSk);
      expect(bdsState).to.deep.equal(expectedBdsState);
      expect(message).to.deep.equal(expectedMessage);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(error).to.equal(null);
    });

    it('should return sigMsg after signing the message, with message[0000...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const n = 32;
      const height = 4;
      const w = 16;
      const k = 2;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '00000000eda313c95591a023a5b37f361c07a5753a92d3d0427459f34c7895d727d62816b3aa2224eb9d823127d4f9f8a30fd7a1a02c6483d9c0f1fd41957b9ae4dfc63a3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5dc25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d'
      );
      const bdsState = newBDSState(height, n, k);
      const message = getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '00000001eda313c95591a023a5b37f361c07a5753a92d3d0427459f34c7895d727d62816b3aa2224eb9d823127d4f9f8a30fd7a1a02c6483d9c0f1fd41957b9ae4dfc63a3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5dc25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d'
      );
      const expectedBdsState = {
        auth: getUInt8ArrayFromHex(
          '3c89f5406198c1397ba5218f771a51549d5e6c62c58539c283189cbf02899fa6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        nextLeaf: 0,
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        stackOffset: 0,
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('3c89f5406198c1397ba5218f771a51549d5e6c62c58539c283189cbf02899fa6'),
          },
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
      };
      const expectedMessage = getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000');
      const expectedSigMsg = getUInt8ArrayFromHex(
        '0000000010ddfc3f7bfb9c95cc48f4cfac1eff2cbb03c0d0647e41a84de8d3ecebfe0bc25de56f7576ad9102ded6416dc48db619c7ed28e4de8f1a1fa4caa0efd9daed970c8e9f0f7de6e0a592af8fbbbe6495caa90291657ae3581857e216f3087ad0d00c9948edf953d8a34c4ac0cb9e6720085e30f8968f0f46d764841c42376b1f49920d5931da14880ff98f2400a65d1fef7c92f9395eb14f92607e49a0988247561e06ab0ac0e5658df3db83b6bef8ddc37ab4516d5cd60c0c644db78fb2d63e9c5d39ebf4128275174c668ddf9a52b25dc1cdfee39ed5452e07a7edcc3b7693c76e0b075e19fa8c275b9941b517655222532b63c18706cda97f4c32a07204687313509cfcaa0a64afa572ed1afa80aa485a805b456b28fa244d758e1fa2b32835eba53551b95c22e8800f0a895890da6436aaf25ee48b030741dfb6dded712d1df29c7e80aa1f70165ec8912966ce6666a6c3665b3450ec2e15e29e780f98b2ffec00dcd3aedc2d04a43ced47d1c52917a8528fa6a46c77acc227d68f546a12825fcdce1b2446fbbc7047337e8eec296d9259d75ff4b219d636d09823926ae57bc1d8e05780048d2775510244635d06f22c48ad299e006882ab7eed2b0c586314021a6813bf710cc1e7e31be9307fdcdda15e84d3ba853a029eb1732ff6a5560931fb7634ced4948e1046af949a95d5b3f3510e8921b7db04c9dfd8553537e7d8dd26a0c93438bb3ac396bed58ae3d96c19bdaa6a1bfa1cb8b3eeecc0458a1a37c4d779030fb44ba1020e79c56dceb443868702a07181f7740dc51477928da631b52b928d0b81c9a37a49a0a6311c16dd6229bac9d890ac8ff2d369d6c89d5638a87f3da2a2ed0887897d8e38b10189bcce896be4c26378f5f62a93a972db058d7f8025094b19d4ead94e804f35323a8891d80a879fa062cb3954d96c6451a768ca3073f689228c629b212dde2d64605d81b7f663cab4d0b56b9e43edc9a58f92b6a4a03dcdbe60fa43129e67844a867d350d668a2f3fcee26c92e5532105215fcb6e63e60c4bd9d73a3f61669ab872b4725690c6304d9bc6adcb3f564b180fe4acaa4a37cd4d018b3a0dc11653ac679434631d7b27247feca64a8a05d971d4b3238ce4217d4b290235b01e54b9de69fd01450679b164c45fcea8d873ea4bd0b0377d36506a98392e28fe81c525703da9e4a636ef4c1ac990b727869da2e54a8ed275752b8ed914d90bc685ce572a83032f04f266d8bb14f450917c91cc83c7e404ad2905cfbe4ea2e40b757c7e3e4097f6b4ac9157836b1ea4117fcecfb7524964f60455984c0574adffea289414dea5332c281fc658aee02d94859e0f935472358234dc9b8b6a44a84a843ddf08ca21c5c79966e7f5074c6dff2b040b4aafd58289d82ee1c1dbca20bb4fad1fea4700c729520c07d7d7e071d066d1dcb50fadef56a9a56eca9b09482f05138f4d2259839c80ae1eb3f10e27233f8761cd7a6786924d6cefa7aecb610dc146ed92a6ec9d34b4175cd13bc54f202084fa4c5b81b9cb846cba0d501edac1dc9da8c13db53abf61286b5da7c1d6ecb29e2ed4aea9057e687707d69884b61686894d093e2ce15b825188602d9f00f9513dbf3b2c2fd9b0bde3b8313556c3c981cb70c583879cfd2b2e8d67cd4c8749a8ee29d42bdac9cd5ff44d8375c495fec0780051d805e5e62612393b24ea292324c9d458517ca5cf06f9bac9ddc84d03d20c79ff8d54df297c4b630d5fd19e75621e7526916740065c4fc74a2466c32c6d9f0d9c4dee6b6cc40c4e35e77d79a72ec1566541823e0acbd31022ceafd58710289ac0699ed6e25186638c37979a0e57f2db0d6139608b6bff3b48d62ba87379f642a002561dc38abdc9b799e0c2d0356f714914f4d4316e3ba770c4ab7e30c22be0a0b920f1324bedeb283e202a9daf87b4959cb11617a1f64d328128428fc7cc7947bfe15259fd11a8bb663916a28891dec8334c1547d37151a05fddfde0190ada322dbe9ddb83eb0595b2751827782b9ee78e3e90a01f1421279fcd0dcf10969d18633c4ba43cbf2a8364fa22c3295d471adc41651d0bcf36751fe49e146cb85d5f3f9b9c6730bedc6388e638d1e65c81f9254dd62ba8264c1ae016f9cd33ba50a157763ca3d17491b6a487d6398bce9ec36882aef84d0cc078ddb329aef1962c86af39256bc65ab926526ea8d7b290baadf2145d4e0acaf30c24fd6d603c1b3cff1a6c51ff41e4ab5f61acbd0bfd0cc23c18a684e40ca5f1162b08c241956792855ea29712c79ffbeb04df32d027fb68da3b667515c051a40715a6781ecc0313fc91e8d44b8efece69b2c5331dfa13a9061155326d106a21b3c20b84e0c8b2f9ba7017b66434ecbb9f2dd6faefc67cdae962fd9f74093b52c9e32891b190840cd6333fe4e4bf59508529e5ab3b5b1aba83565ff5d47a3a07b55abaf2a462ae06cfe7e72bf4a18703e3c2a840f3fd1f263614db72f0d4e8391e348b11718319324e8d16537d179bfcb038997555b67deae186819a61ae6297af9db1e313eeaa9b58c3b2b7918f1ee34c4461e8912dd2944abf254e9a2e36a99c392065408b031251ff0895b7e7231d475852f6d51ac450f491ac76cb8dad053b511a17fcf39981165670ae5eab6118c506bc1c67c035e525dd23cc6448d7b8bc2b0cc21a2d30167d43cc8fe6c6373a041b2a2d720dce845be178cd51e81f2eb6931fcd1e63778550600e91585cc832bf4d22157badc5bb0da1e12fa0a03735f03f38751c0bc64ce04905071b76d9cce03eeec0eefe821a028f4d18dfb2e8d11563c6eec1b08ae78118ac3d62d79540ecec0e11f9fc5f51d2fb3867eea45c1fb0d9f03a30d1798615cbba470ebb6028103809d504cacac26cfb583dbcb1104aadde5b332b6938832ef91f57c8425882c27da1fc8a573f1d9ac38798f5808624d64c95caa2b1009ab5d1ba35b03d43afea31cd4bed53ab57ea8c6009a204b0d30e0ad633a436a2b716860184919063ce5addac04347a1beba3d03e41ed6ffc58a917b13fb64f1f36c5f7244dfbfa5465ab9e5dde9d41b875f230140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const { sigMsg, error } = xmssFastSignMessage(hashFunction, params, sk, bdsState, message);

      expect(params).to.deep.equal(expectedParams);
      expect(sk).to.deep.equal(expectedSk);
      expect(bdsState).to.deep.equal(expectedBdsState);
      expect(message).to.deep.equal(expectedMessage);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(error).to.equal(null);
    });

    it('should return sigMsg after signing the message, with message[68bc...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const n = 32;
      const height = 4;
      const w = 16;
      const k = 2;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        'b10217cf714044a891a19f3c17b2675010e05d5ea84a96b181926995df5bbddb523b76517fa322cf5ec537fc6a7f74a6f0110f996fc65a6a9bd5f2b8aa57aa68d5ce03e4deb53ed6d976a317d03b250e8702f68d9e5d0a41c5ac6c5ecbf14eb6da7228aecfc651808cdd9fe8a1377d907837a2c092e12ac8083a55de904f54b292c40867'
      );
      const bdsState = newBDSState(height, n, k);
      const message = getUInt8ArrayFromHex('68bc27593ec688464622c15e820e54566e1c97f6ca4fb4ac769e30931fee1952');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        'b10217d0714044a891a19f3c17b2675010e05d5ea84a96b181926995df5bbddb523b76517fa322cf5ec537fc6a7f74a6f0110f996fc65a6a9bd5f2b8aa57aa68d5ce03e4deb53ed6d976a317d03b250e8702f68d9e5d0a41c5ac6c5ecbf14eb6da7228aecfc651808cdd9fe8a1377d907837a2c092e12ac8083a55de904f54b292c40867'
      );
      const expectedBdsState = {
        auth: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        nextLeaf: 0,
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        stackOffset: 0,
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
      };
      const expectedMessage = getUInt8ArrayFromHex('68bc27593ec688464622c15e820e54566e1c97f6ca4fb4ac769e30931fee1952');
      const expectedSigMsg = getUInt8ArrayFromHex(
        'b10217cfb68feab85b43a8bb0b99d1f5c21784a6669c6198d58d7eae1c3614365f942e1ba971b9ff4499a52452ec0e1fcee17fcf6205af0058fb5614c862029efd1207a592c8a8ca432e6366d785bf1a3f250d730d585b451d6ad07dcc2e03cb4d436500f3ebffc9b70df3fda22089243739a20b274ab60d3e0fda3da74eaa570c05b2230063c5de3d9d6aa5d7db3676f746ccf8464c6543aad87b57364c94f297040f69efab3016303aba168e39aadd3324efeec6ec6b6f3b028908ab4e2684146929c2d65158b31690b074f6caccbd697e6791bc894d90666690df741cfb1a4e91204375b97fc172c843360cacc5f21be796074646df579a4d6d52144e2b0d4c0b5ecf00b7e19607c6fb2501484e6bf172e94247b2af5a73803dafff9a21c86a603c4e08a9355ac0b5de8ff7a1ef823ea2c66eec81e91260aee05cdde02b5f4a347e16bd747fc609e62c91939081c6e0faa904a77ee5763be8057d17d8dc68cff7c0792ab0b6648fa63cbed273db2085019a9ef66124dea5c0158624073e9392d3d5bc683280b0ca51de896c1bb0ecefdbd6a851704ae492fe188f056e87ac7ca200d43828dafad11e647861c98bdbc9d1d7e041144a0a56495321b16a09d4b3e373a3f15cedff5db3eabd32a0d0d65c62b86f575dc32ef550a1ef2fc3a4da624a6b50df9ee7a6fe41eff18241478c47b609dde603c56bdc4ff95a3199d0afa8d6c1997817966cc497e3428d9e902962c1e914186da0254d9d9e4a10ef7ef47ead8215d4a60b49c9d4e7508bf36c96d5b553abbeb517d83e8cef4da4c671a92d4d075640eace6912b2466f45d95f5260a9e4de5764b771c396393467619cb59d370e71ebe41e4f9414aa773b5800299a20f7f207e0230ca1b05b89a099c576f3782557ec1b3734181a42a92a96b90d93b3803a7d44247217ebff80e0d0ae41fd0e26a6e56cffa07acc5aecfb833d9aca96b57bf4716848c1069bdbdc85fa3729c518f5434e05fb6d1f26f7fb751ca2ed5ab7167c8cf77076656a96e02ddbc2d8b4279e676e4b9cd72f2fa59e2d698cd733a468ab4d35a44c8c2eb12a76d6e4686ee393938c52d5964157bb8593306e0e96e3bc52a32e6d9b2349200674b93e253e06331e35564cd89c8284097b8e7e1d35db7a337a3ef449a28101063c37d019046c4129489d155ec2d5b9227aeadb194af156a3c04d412ad44132454a0dcecc322d55d693d6ad5267f3489783111fe922eccdbb70ac2899315ffa58525b2273a746d892dcf895fd5127020d8684c6b09cc98cd3d2f146ad519896caa33835fe12b8ad66eb7644ea26bd1a8510d268f76fa2de8de18e59f4ad7ec618d4bf8942a5241b8f436d92559e3824a51513029f607bc8e6b151417a84cafd78b0c91e058ebf6542b276f9d4cbdf207c823bdec310a3188b3df3fa05e5dbcc9a6b982c6a8eec1fac9c6d754e767c3b53df0ac55b7805ea1083c05475c0f94ece557a12d255b68c947e4ac41d3a8e7dcdb6ead352a307494ae4aaa3908aa969319a80803ad1704d65c9ab309317cdd87ca09521715baf75fd6b6fb95424b2ec519202081452ca9a79c342a45152163d46831dc9471b814a98c4cb186c540a90df1e4ed89882b2c3acb90e8e5f6590e9022ea91ff09f73887b2d684131b49b393c6b60bda610fa0b668fcc51dd729010f1fce271747e98614eff3dddb20ca5f1a98b600978982ba05134ee02c83f693c403b8113435e67e60022513dd912afee0be3453a4fa0d12e0fa90b1e44e8a713f04e9309d74c2ee3b39f2b7164a23d07dd14af03a66274802a7f0345d39dd7f69f442c0f8e84504b0f95bf3522da99572ad2074bf18dc3ae83a83dd63b2a70c674ad4d4cd63c54cac706728e70a2928ed5af8fa8dffead16a6c24a966818ffabe612e2ab5f355f501bd2c0a52661f95f49aa62df82303e00e568db1709719c815db69d066462da6f65199918c23dfe3a2efb0b6af994d456ca4a47a6d2cccf3cb6a1001655baa3e9e41343b725d39b1f19050fd30813e6edae9b67f078035c45c6ad9b27262fd052dc9517bb4120ed6378281956a5ca8308a4f70ba1d972c1857cd217a6f3cc8c6f56248654a099b7fa47b5e64af0540b670268e526036649aedf036bf332e87b2287b13a96905956addad694ecb4e3b764c7541fb4b88d0ca9b77d0205f8903feab2da401882e05d1a6457c20636b2956df65572fe7f50741ccef08e155c11cdffceb858d90404105e5b1bcbef142ba6c621e183959ebe587ce596de15e132f8bc9c7626ec561285b739bdb5ec5a4a98c1ca23802f9bb756311db219a22308f0b44856887b9b0076061dbdbfa2a6d2ccd2158a57b1138ab99f1199998e186fbbf094a1e950914471f05d4797666d39748fdee34da0066810680b9705788658a0222f3b083579a787fd6a1cf2cf11ea10dfa9046e420f280f88896051ce5195567c74213815fe5cc24233cfb2a3626a774877f559081e0a182b8484e760e0e0f17cf7050f6186896fe89e01c1f87c18e0c8e20f7b587876c07f04e967ed4f52d42134fd1476a0a62197025cd8a66681d9addbee248b5e48330b2e8476574db08e340a7bdee3353710f6f809fad9bcc4fac10ea7a7be263abe14c498f7c4df580d61d325948fd4251d5b620adb60ae90054f3bb616acd5fb5dd4144e4f715ffa278c7429818556812ee6c6209d24039372fe429d16ae910eb0e61ab08125340d0289b756fa476097d239944b0429ab953025a81f9e092e773a37c1af74156251a593a658033d3be4128792e83dc6771cfc4aa58e71ffedfb2c76f830997f5b88d8805db98fabf943e0660cc825e86ddff8d87fa0b14379222e05d3fbbbc2634086720cf127dd0c92ac6f111c0a56f9fd15d80403c8670ea099daa7a085ef5c4cd5f4af4f8341442166c616461573a627821a696838ac1799600d03579dc1736b4cda203323367092521d0cd6bbab795a93c5a8e35436d177f04dbb0d721ed2775496f0c2575e92e30d0d067a97ff6584e41ce1c85094cf6285698c592339b6e959d940fec50184ccaebedd2073f41a6fb2570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const { sigMsg, error } = xmssFastSignMessage(hashFunction, params, sk, bdsState, message);

      expect(params).to.deep.equal(expectedParams);
      expect(sk).to.deep.equal(expectedSk);
      expect(bdsState).to.deep.equal(expectedBdsState);
      expect(message).to.deep.equal(expectedMessage);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(error).to.equal(null);
    });
  });

  describe('getXMSSAddressFromPK', () => {
    it('should throw an error if QRL descriptor address format type is not SHA_256', () => {
      const ePK = getUInt8ArrayFromHex(
        'f0808304878785df7a4420c5e4b212872088a2f6960fe9662dc77e284bcc55d17f325108f8305a7c2e9db71c5a894b5d591d2c71adbe926604598bfd9dc5e8251866a4'
      );

      expect(() => getXMSSAddressFromPK(ePK)).to.throw('Address format type not supported');
    });

    it('should generate an address for ePK[de00...]', () => {
      const ePK = getUInt8ArrayFromHex(
        'de007b7c70da3ded89c76163141d39d445d27fea787436a504d69f380737458550a209af1146b2a0b5b72183a1f3bf7e1cc79f8a67d7e316a4e9c4178bd57f9b60f123'
      );
      const address = getXMSSAddressFromPK(ePK);
      const expectedAddress = getUInt8ArrayFromHex('de00009aa8c7840ae79807d403a58c37264eb2e8');

      expect(address).to.deep.equal(expectedAddress);
    });

    it('should generate an address for ePK[ba00...]', () => {
      const ePK = getUInt8ArrayFromHex(
        'ba003f64189f348426066c252747f734c36411ee6ad24a13680aae810e67af27a932950a76b0162c3080a0b9031995b6de8988bf98f79e5308acc08e2fca89eacffbcb'
      );
      const address = getXMSSAddressFromPK(ePK);
      const expectedAddress = getUInt8ArrayFromHex('ba00009f802eb0bbe78624fc8db18a76617e7249');

      expect(address).to.deep.equal(expectedAddress);
    });
  });

  describe('newXMSS', () => {
    it('should create a XMSS instance', () => {
      const n = 2;
      const h = 4;
      const w = 6;
      const k = 8;
      const xmssParams = newXMSSParams(n, h, w, k);
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const height = 10;
      const sk = getUInt8ArrayFromHex('202b2c0d0417');
      const seed = getUInt8ArrayFromHex(
        'bc2625f3f73b4424350bcf21b2a10afa5fc8cc286e0e58ddd4b76d5b8bf28c5043db2f6f83ab1d9f62fcab98f5e54e45'
      );
      const bdsState = newBDSState(height, n, k);
      const signatureType = 3;
      const addrFormatType = 7;
      const desc = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);
      const xmss = newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc);

      expect(Object.getOwnPropertyNames(xmss)).to.deep.equal([
        'xmssParams',
        'hashFunction',
        'height',
        'sk',
        'seed',
        'bdsState',
        'desc',
      ]);
    });

    it('should ensure the XMSS class instance has all methods', () => {
      const n = 1;
      const h = 3;
      const w = 256;
      const k = 3;
      const xmssParams = newXMSSParams(n, h, w, k);
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const height = 10;
      const sk = getUInt8ArrayFromHex('4f7346');
      const seed = getUInt8ArrayFromHex(
        '941b1a21c712998a0de96488917981741c007ccae09a457e1d33f678d41fb961824e1a943062fb95d3b65a241e797033'
      );
      const bdsState = newBDSState(height, n, k);
      const signatureType = 3;
      const addrFormatType = 7;
      const desc = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);
      const xmss = newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc);

      const allPropertyNames = Object.getOwnPropertyNames(Object.getPrototypeOf(xmss)).filter(
        (propertyName) => propertyName !== 'constructor'
      );
      expect(allPropertyNames).to.be.of.length(13);
      expect(allPropertyNames).to.deep.equal([
        'setIndex',
        'getHeight',
        'getPKSeed',
        'getSeed',
        'getExtendedSeed',
        'getHexSeed',
        'getMnemonic',
        'getRoot',
        'getPK',
        'getSK',
        'getAddress',
        'getIndex',
        'sign',
      ]);
    });

    it('should ensure all the XMSS class methods are working', () => {
      const seed = new Uint8Array(COMMON.SEED_SIZE);
      const xmss = newXMSSFromSeed(seed, 4, HASH_FUNCTION.SHA2_256, COMMON.SHA256_2X);

      expect(xmss.getHeight()).to.equal(4);
      expect(xmss.getPKSeed()).to.deep.equal(
        getUInt8ArrayFromHex('3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d')
      );
      expect(xmss.getSeed()).to.deep.equal(
        getUInt8ArrayFromHex(
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        )
      );
      expect(xmss.getExtendedSeed()).to.deep.equal(
        getUInt8ArrayFromHex(
          '100200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        )
      );
      expect(xmss.getHexSeed()).to.equal(
        '0x100200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      expect(xmss.getMnemonic()).to.equal(
        'badge bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback'
      );
      expect(xmss.getRoot()).to.deep.equal(
        getUInt8ArrayFromHex('eb0372d56b886645e7c036b480be95ed97bc431b4e828befd4162bf432858df8')
      );
      expect(xmss.getPK()).to.deep.equal(
        getUInt8ArrayFromHex(
          '100200eb0372d56b886645e7c036b480be95ed97bc431b4e828befd4162bf432858df83191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d'
        )
      );
      expect(xmss.getSK()).to.deep.equal(
        getUInt8ArrayFromHex(
          '00000000eda313c95591a023a5b37f361c07a5753a92d3d0427459f34c7895d727d62816b3aa2224eb9d823127d4f9f8a30fd7a1a02c6483d9c0f1fd41957b9ae4dfc63a3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5deb0372d56b886645e7c036b480be95ed97bc431b4e828befd4162bf432858df8'
        )
      );
      expect(xmss.getAddress()).to.deep.equal(getUInt8ArrayFromHex('100200d13a0adbd6c1791dd6e605e619052c585f'));
      expect(xmss.getIndex()).to.equal(0);
      xmss.setIndex(6);
      expect(xmss.getIndex()).to.equal(6);
      const { sigMsg, error } = xmss.sign(getUInt8ArrayFromHex('89b8ad7c15d8019236b6618852316cbe9b0642962156f2ea'));
      expect(sigMsg).to.deep.equal(
        getUInt8ArrayFromHex(
          '00000006e4b9c00b8c3ca8b3d8cb05fdc36eaeb2ec055ca4230d02931dd88796470d3399f7dadc2e400e2e767f6e97a55b8fbdf2cdb261d36ac8f2ce670ef9ff8b77e3fc236cfa4ca446c9d9f5487be71fe51f64b0cd4c7d75e95d45e8bdbd6fd15445f781dbc932c89539f35e167a8c981c87bada9d7104874362054235dabb6f4f06aa678683d625920c44e0507a944f42df945e645a832fcfc52989c2d1ff4e9d4ffeafd37648098ce401f4ec01a9e3363c2ca95acf7ad061d9943eab01017415bd57d9d6c379919bc9fc127ae1a3b175dd44ecab5304a1bb92db0f7f7e97e0b9b57b32b69b0d3d24b78f6ac987129271ecd8ff1f278b61dce409518bcf18449b9652c9a132340ca270329ab91dbb4b480fdcc94d84566d920e405e2354630de4241f630997121f0347567f4b34a51bc9ffb7278be61f0951cbc0e3b85ceb8399124c41b8b180a501303ad9f5a357486254f318d46d59165f1aaee154f7b67bcecd8f495462fc6a7bd64962267286ff69e0543fdfa6711e7a719d32ea6fdb8f076177330ebc3d50df1910fcd661f8f0423d00c8d1631021e3538604d80047f91a110020436ec1842c72bb9b5f3a4eb82c977214a0898c7fb03c5a08481a61da98c66dcb22f39c492cc5d04e09e326c62d45e05143a6198cb7229f92a746466789e513ba45066617a007685fa74be5f3e47ff83bcf4c371103c1c38701af6e85c9dea1d92c72939ad6c61b09552d5dd3cf8440f09808d5ff7ceeabfb317120dda8ccd12908ae192088e60e7fc4c1d47644e71800c5ca10052901442eab0cbbf9b14c9b4cea21f7cf4030721ea5a13d03fa6e99c283171ab1d7de6e5f3856cf53154115727f49f684eec25e1e36a4c63112f7727eac5fa006c1e6fa048fb436d3b40cd1d2a8715e4e4f4ab617c8865902de9d0e18d1a5cb60be090cb5b8e920151773c2b34e52a46b1699b0f91bfc033358e646032280f11b1c7eb0981e1d6fab164593fc6426b618b467ce72ea8e4856a89b4440677b8eeec63f818fcbb17918cc1ed4e8b7667076523b9348fc1b60aa2eeb8c90599b6578fdb55916726a79675203448d1d1dbf7f8690d272744405007c8fa349d6a08ceef3fe3f3d7e534727df099eb0c91192b723fd1121e305583e61e1997afbb0e7a843ef8551d32117904d551bc6fd756b10f28fc12c76725d0fe9e16243d5251cd9e88413a63ad4211e0185b2dc19a0953a06d19aab79aa372d98f40bfba282382b41f4aa1ce61314a5315d955206de0a26b456b782040652ee886735466b499c0fb4c2f4e19e9268be4c4ca3e00e6b4b849c9e1b462fca0560baacb3f4758cf2b63e063c6fe2bd19093c118a10228c9cdf773f11a25b34cfd2807577500ebed152e61be909b49bb2f57b0076665fc146feb2928df433909036f9cf96d72b64b1bce0598b7a7efd62353144a5296e5cf3c1458705ee8bde6f39c57fa422f71131a916e3c254d708a35b7b7ce31de83a45b449d18f515497c3578648ac060efe73123d9bdfede524f611d31fcd3f6de9d2353b9096b7638cfbdba0194191d4e807ad4e75d20f9fa29eb65b5b9d0eeff229dad0c341871e6a15273c28e7ffa70ef60679900b761c30d250cc319132c09a1f7367079a39dcbe32d2f854974ea2a4a4e61b646fde21e7c740fd05afa90f60e5a7cd3120e803549f2dc47f3a9bc34665e73865dfa2c8cf97c28af3a14ed9a694990c652d0397a3fac17310f4474e2164b4107efddfaee32b690291d35e0d51523780b7c2fca80c19ddde7c674b7c54769888fe7f4262fd7f211491d7ea277bdeab2361fdd651760097693f83b9a6891aef7d3dda648ed6eacebdb995f380985022096a7574ce8ff94c4b29be4805031b6850786e2b4497104ccdff5b1d37a79b471c6a1f6cbff69918131dfaeda79d702db3c85bf8cf57b64ae5f88a3fa3184a490ede80e501b91b94b1a6ad111464574ed19ca1bf3a53314504b04e48a73e9a41e54d534069e8e6b678c960a2edb21498ea5b317a84c9dbabbe7660bf3fa30694daec91ccd3f3a95e084848bcecf1dde1e79470dc8c4af3b651ef0aeb41644028abeeaf0efa50721e8a60db6ed1dddd6a2af9c863fc9628cc4445ec8f22cb552dddb1b4394eb7169057c50e419ca16b49b1c45ae913561d7c4fe861b62ff067f041e15a39b365d4e62eb7f7551b43c280252db33a48fe4d82d35a9837a560b084291304337228e6477c9d2856eb5cd820c0eacc12503438932389441ce315bd972363f0403e5db09140b287c946ed254025d0630faf0f756cf7044213a22011012d07158ef1f64926d316aa67d78221ef3089a55117554c713fa0ce7e30a2c605adf5de1a76cb2d95ab1a4bfec5bf69c0f10b5c1c9b1dc12ae9774838d97173715b6c22d431ae320a15fc78947ec4c54b68827c39a28493b544d9701ec66c4f58879cff0d024a0d1628507e6c3a8dd7bbe54b89d065b46efb2bb6b33d5379358b42693cfc29704c523f636b1d5d228af1263aafb2c2d3cfd24255747af2662b9229f2bcd5b4be9d17a2284676a291d4b91ac557a646a02c633ee2afeb409308b5632b27cee9561497fb42357a68b68f7102c8042eed27348fd6aa3f846a85eadc2f342fdadd20bcac2b29c4b735fc9dd5bfadb578d4d4470fd8f1ed0e666a1af4fcc614479100e06a457a1ba865e72c3c82bb0cf4f1ce67036c544f28c8b0e857bfc71fcab80f0a804d0237f4c6395018ff41b1a8a77ee5992f88f42b6f976693595a1acfd54df1749ab2ed2cc7a37be8b19f5e0fbabb7f745e01bdf25120314fb81fe2764e34387ee78d0d25e59c34d71606b161b7a801cd410d7a2a87e48f0543fd492ee85a22526d06c9dfc5ad34a279affaa69267f6a69f0a14ab1987a16633ed4fc521f7cc03477e10c40d9e3255f8d67d115bffae66103b5a43d63559e3663e993b9bf579d9fb233cb26e2d18414e983e68f9c808d92124b14d4a8e508c2b3344311920cc4f2697ff3f909cc78e8901249ce95663ecd4a838a78a8dcf7950b3aa3f044dc9bdbf3ef8095501ad8f2912c4e6b2ea2a9e0ff1f1c9809fe61c902b25926bfc2c317973cae4013d63ff4001edb438f8d4e1846d7e7c453fac321afb0fbeebec6c272a2f6178a71e85c593d27ebc0ea7d32f5ba37d98d965868de234b7885e40175ec48ee5d9b93831c9859223b71486a2da6187043d55101e1919502f6f1f788b3f95700efe2e177f03e06a4e81ec4fa0183b787d'
        )
      );
      expect(error).to.equal(null);
    });
  });

  describe('initializeTree', () => {
    it('should generate xmss tree for extendedSeed[0592...] and seed[0000...]', () => {
      const extendedSeed = getUInt8ArrayFromHex(
        '0592b6e072fab5ddc98a84544f4e9ebf50b1879705dd54ed5e985412b8d3140a09ccfc0cde7283dca76f93cf8f4446e4d96a49'
      );
      const desc = newQRLDescriptorFromExtendedSeed(extendedSeed);
      const seed = new Uint8Array(COMMON.SEED_SIZE);
      const xmssTree = initializeTree(desc, seed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 4,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '00000000eda313c95591a023a5b37f361c07a5753a92d3d0427459f34c7895d727d62816b3aa2224eb9d823127d4f9f8a30fd7a1a02c6483d9c0f1fd41957b9ae4dfc63a3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d0000000000000000000000000000000000000000000000000000000000000000'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        auth: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 5, signatureType: 0, height: 4, addrFormatType: 9 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 5,
        height: 4,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for desc[6, 1 ...] and seed[4418...]', () => {
      const desc = newQRLDescriptor(6, HASH_FUNCTION.SHA2_256, 4, 44);
      const seed = getUInt8ArrayFromHex(
        '441872e7d62b779170e89c1658a2291bf5ab5add025b52530a8c49197143a6e039c2f43cfcc5a8fa03803eaee25a1065'
      );
      const xmssTree = initializeTree(desc, seed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 6,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '000000009a7c2a79255bf604f4c615fb1c042348bad4103a410a47c7b3f329ff82e4e5da6796859f1fa972176576cd02455df41c1e4aca33017eddc2ad6c74efd89fc4786a5f171f8973c643aa9e708dae57763b5603a3023d88befac0e4f02e7abe3872f1445b68025705334afeeb5f62927377156b14e4a297d13d3893291a1663f956'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '441872e7d62b779170e89c1658a2291bf5ab5add025b52530a8c49197143a6e039c2f43cfcc5a8fa03803eaee25a1065'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('00000000000000'),
        auth: getUInt8ArrayFromHex(
          'efe6d2d12a381e54140deb832bfa48b533cef35d7bd11996a7064b8e212645c2a8c2402829d86933bd05b15a2f2e11a8e164de8400fe17bd209b63e628aea13dbd422519a8a118a978e84976d277b6ff153da7846ebbcc8058008e6db129151674a757ec038717c9c02fb64bd80aa52a2c60c7e428900704e04e552919d545cb2043b1b398e99051979e160e98455d2e6020145004623417f8f027d8ed4c9bf2d913e21d54c7bda777d51a77a89291888873900f15a187d6235b5b40150eb97c'
        ),
        keep: getUInt8ArrayFromHex(
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('d422fce80bdee7ade1b8ab2ab61747318ca74126caaa58cd9dedfcdaf35c64f4'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('28adc78bb4eb245994fecc80cc2a8044b8bff947c1e460fb608d2efcd091142f'),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('ffbb8cd77290f48df39a212b7c06f11fe68b52555caaeb1344c2cdc59e1fc77e'),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('83acae7432271bc58df7c401788fba62190fab45fa6b68cf6744fa53f11ec2bd'),
          },
        ],
        retain: getUInt8ArrayFromHex('ff3d705ec5ee94cfee5dcb2121c6842509172c17b7003339c4ac2af0edb7f283'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 0, signatureType: 4, height: 6, addrFormatType: 44 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 0,
        height: 6,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for desc[4, 2 ...] and seed[112, 104 ...]', () => {
      const desc = newQRLDescriptor(4, HASH_FUNCTION.SHAKE_256, 3, 7);
      const seed = getUInt8ArrayFromHex(
        '706889c069ab23df5b0cad70b776df8d3f107d43474c1c741935641dd6e8f5d6965616c5143660fc1528392a08470023'
      );
      const xmssTree = initializeTree(desc, seed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 4,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '00000000278753f1885de207c878d28bbcac22bf034236d49eded22fb9c0d721cec2dc85f8ecdef17695ad7f0c463ba2d11043b22c462a05209b573ee5f31df9c2cb95e877dd3069fe95f002d1bd797cd552b34b7f74a6d465ae249ec6926e79a3a959f7fae92def8ad5618a163f7e43ca4d3b72b5486ceaeb8ca6f2fc8349ad8e05f8a3'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '706889c069ab23df5b0cad70b776df8d3f107d43474c1c741935641dd6e8f5d6965616c5143660fc1528392a08470023'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        auth: getUInt8ArrayFromHex(
          '2950dc82c803bb1408d362dd873ddce0b6b86d3919509fd7ad45d1fb730e17acdfd751f280570683f8d4c8bcc32406ad0035217275c6b5a055431d98aa006ca7e1933aa1160b458d4ccb8e30b02f82475fa65edd44e93cc46d83037727ac934bc2eee70be93f5b9c6a4879ce41cc242591ff8ca446415977087d639f339ee474'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('8ab4906fd7c82265ccfca85ddeade87a878480bfeb2a4157450c8d370fd47ffb'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('36550bb3ec4858a55530c2faa7aaaeb7f521797b4c384c423ec530074cb6c12d'),
          },
        ],
        retain: getUInt8ArrayFromHex('4fae93d679cdb37382d934d86a14fc396819267e6d9f5f6e439060f13e489363'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 2, signatureType: 3, height: 4, addrFormatType: 7 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 2,
        height: 4,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });
  });

  describe('newXMSSFromSeed', () => {
    it('should generate xmss tree for seed[7a0c...]', () => {
      const seed = getUInt8ArrayFromHex(
        '7a0cacd6efc210a171a661ebcf5ae6d83d5a2cd5e21e835560246a2573a99eec11abeb4d32eb5e2a15de235797ddbe25'
      );
      const height = 4;
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const addrFormatType = 4;
      const xmssTree = newXMSSFromSeed(seed, height, hashFunction, addrFormatType);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 4,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '00000000a3f85d8abafefd819fd6809c765e16c13b63f19c1a194f37e137fe0953be874503509d30aa3e1735f44832685b289790cc4711a06a51919b96cea4163affe6cdc5cde53649ab0dbccb459c5d6f9c563be84b90998ff1d66ea19b8737be0a3cdad734366e01e1ca1d78a6333902b71a94d5ad25d313966e0ff98a0408b026deda'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '7a0cacd6efc210a171a661ebcf5ae6d83d5a2cd5e21e835560246a2573a99eec11abeb4d32eb5e2a15de235797ddbe25'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        auth: getUInt8ArrayFromHex(
          '2717ef867895c915feabc5339a62688a149be6b441395b1230f80f1e7ecd7cece0b54a69a292710f8a9c2bdec75f47e30616741d485327331acf822b5d664b16978286810487f369b1919524c657dacb060ff4f5d4e02eefa11dcef4203b3ac9d61e39a193995606ddee00ff76d4cc11e1adec5fc7aab56e3d9c7a021368b052'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0e557f9aec0fca9e70facded24faca5f960c3796246f229e2af465fef8545482'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('12ba948d6f1048fbf7befdd5c6e544b937a7c34ab499aa8e835b78f9964d0225'),
          },
        ],
        retain: getUInt8ArrayFromHex('a5a5ed63d1118a9429b4a7b3e4fa9c4c3f136804c865c23257a05aa61377cae5'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 0, signatureType: 1, height: 4, addrFormatType: 4 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 0,
        height: 4,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for seed[6b0b...]', () => {
      const seed = getUInt8ArrayFromHex(
        '6b0b88df1109a708340d46b73406949e27e69b14f0bc26a2ae9a229e5346e15884cf15699b5907f7ac765140137addc7'
      );
      const height = 6;
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const addrFormatType = 3;
      const xmssTree = newXMSSFromSeed(seed, height, hashFunction, addrFormatType);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 6,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '0000000096b28f84e978f3cb62f9174edad118ea3526031e1bab1a8635c87258afe7426409605c283954cd4eb92b55fdae89bac7d9f562cab676b47583714f446951f71cdc07ad289c9b5eaf908e86084ef01dbed124bbe613b8898a9530a8f7ac9ec87bc1bb2e57cd4d485e875a5277b1ebe79bdcf41a5b94551d98a4f7c1fbe0fa4413'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        '6b0b88df1109a708340d46b73406949e27e69b14f0bc26a2ae9a229e5346e15884cf15699b5907f7ac765140137addc7'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('00000000000000'),
        auth: getUInt8ArrayFromHex(
          '03c2c0e3e3f575f9907d5e277a69370b4912cb1913b36a0b3c9d1e95ab8f65726f3b38b6ac41eec753c526681450492c1938ab2cc6d10c92e8695eac0ba5949c6a5b301bd0628b9e96280e03872e4319b956a06d9547399b79517a373ed640e1d3deab6f8b6b754873d68a1961296915b8dd5bd2b81b9eb1ccbc87a8c72962350fb2a31bbe972f70df631f8a50a86e76adc3323b2cc404e43a99c5bea621465f994f0d7b48df022576b3b47355d22150770b19fafb05f274f7545dec3dfa5cc0'
        ),
        keep: getUInt8ArrayFromHex(
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('f44c2003aef6a595557805b686322a2e37bc778b20b3b9f06421e026b176883e'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('25cb446af909a2f48c773c063579aee14bd1c7b04e8c37e635fc9a8cf3160b31'),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('99a54735b4dbd5c5b8d18597c20ac1b10aea7f6db0a4474781015140303d3cd3'),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('e0474585adcc9d1a3de99bc4e436582dcea584f7e179704399a87331c84004c3'),
          },
        ],
        retain: getUInt8ArrayFromHex('2347939597828faddde36c96102bdefdac1abd22c4f85134e5fe8daf2ec71e08'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 1, signatureType: 1, height: 6, addrFormatType: 3 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 1,
        height: 6,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });
  });

  describe('newXMSSFromExtendedSeed', () => {
    it('should generate xmss tree for extendedSeed[d6c2...]', () => {
      const extendedSeed = getUInt8ArrayFromHex(
        'd6c2a6d00c1342880a46020bc275df5073b0dcdf0569eeba66152214f26708d2d41555eaa73b13e109113133009e46d66c55af'
      );
      const xmssTree = newXMSSFromExtendedSeed(extendedSeed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 4,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '000000004cc89ff1593b18c5ae41d290ebc3967c8a714b228f1e8d238e16f7f0260a6faf4b0a96eb9a6f8735a6dfc892aa3f49c85f9134574176b7e7d076dfae17d6757d5b1d638e27f21ac58b1aea880bae3d59e628d27f2654abd0b6c1b6344ae132c30000000000000000000000000000000000000000000000000000000000000000'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        'd00c1342880a46020bc275df5073b0dcdf0569eeba66152214f26708d2d41555eaa73b13e109113133009e46d66c55af'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        auth: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 6, signatureType: 13, height: 4, addrFormatType: 12 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 6,
        height: 4,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for extendedSeed[b8b3...]', () => {
      const extendedSeed = getUInt8ArrayFromHex(
        'b8b3accead5fe52a68c64ab7c433937ec8ac1ee0f8f024fafc3a2d42fc297e1d3a5ab0b4937ec69a0682e81c3e182b329ed9e4'
      );
      const xmssTree = newXMSSFromExtendedSeed(extendedSeed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 6,
        k: 2,
      };
      const expectedSk = getUInt8ArrayFromHex(
        '00000000abbc63bc9dd889365399e64710dcde3731d051c2d2037162ab74c699e9818bc8bc60979048d14ba7a0ff90eab65d6eaf1ddb1f8df80bb9e99c73c6a7fac327057cb5ff9d3e2820c228fcb528aa98536a10c0fbee4ad3a7b325c47609af1c425b0000000000000000000000000000000000000000000000000000000000000000'
      );
      const expectedSeed = getUInt8ArrayFromHex(
        'cead5fe52a68c64ab7c433937ec8ac1ee0f8f024fafc3a2d42fc297e1d3a5ab0b4937ec69a0682e81c3e182b329ed9e4'
      );
      const expectedBdsState = {
        stack: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackOffset: 0,
        stackLevels: getUInt8ArrayFromHex('00000000000000'),
        auth: getUInt8ArrayFromHex(
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 8, signatureType: 11, height: 6, addrFormatType: 11 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 8,
        height: 6,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });
  });

  describe('newXMSSFromHeight', () => {
    it('should generate a xmss tree', () => {
      const height = 6;
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const xmssTree = newXMSSFromHeight(height, hashFunction);

      expect(Object.getOwnPropertyNames(xmssTree)).to.deep.equal([
        'xmssParams',
        'hashFunction',
        'height',
        'sk',
        'seed',
        'bdsState',
        'desc',
      ]);
    });

    it('should generate a xmss tree from random seed each time', () => {
      const height = 6;
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const { seed: randomSeed1 } = newXMSSFromHeight(height, hashFunction);
      const { seed: randomSeed2 } = newXMSSFromHeight(height, hashFunction);

      expect(randomSeed1).not.to.deep.equal(randomSeed2);
    });
  });

  describe('getHeightFromSigSize', () => {
    it('should throw an error if the sigSize is less than the signature base size', () => {
      const sigSize = 7;
      const wotsParamW = 16;

      expect(() => getHeightFromSigSize(sigSize, wotsParamW)).to.throw('Invalid signature size');
    });

    it('should throw an error if the sigSize is invalid', () => {
      const sigSize = 2200;
      const wotsParamW = 256;

      expect(() => getHeightFromSigSize(sigSize, wotsParamW)).to.throw('Invalid signature size');
    });

    it('should generate height with sigSize[4292] wotsParamW[6]', () => {
      const sigSize = 4292;
      const wotsParamW = 6;
      const height = getHeightFromSigSize(sigSize, wotsParamW);
      const expectedHeight = 0;

      expect(height).to.equal(expectedHeight);
    });

    it('should generate height with sigSize[2212] wotsParamW[16]', () => {
      const sigSize = 2212;
      const wotsParamW = 16;
      const height = getHeightFromSigSize(sigSize, wotsParamW);
      const expectedHeight = 1;

      expect(height).to.equal(expectedHeight);
    });

    it('should generate height with sigSize[1700] wotsParamW[256]', () => {
      const sigSize = 1700;
      const wotsParamW = 256;
      const height = getHeightFromSigSize(sigSize, wotsParamW);
      const expectedHeight = 18;

      expect(height).to.equal(expectedHeight);
    });
  });

  describe('isValidXMSSAddress', () => {
    it('should throw an error if the size of address is not ADDRESS_SIZE', () => {
      const address = new Uint8Array([]);

      expect(() => isValidXMSSAddress(address)).to.throw(`address should be an array of size ${COMMON.ADDRESS_SIZE}`);
    });

    it('should return false if the XMSS address is not valid', () => {
      const address = getUInt8ArrayFromHex('0f09bc26b0f7120a9d1e28aadf8f6f52724524df');
      const isValid = isValidXMSSAddress(address);

      expect(isValid).to.equal(false);
    });

    it('should return true if the XMSS address is valid', () => {
      const address = getUInt8ArrayFromHex('1309bc26b0f7120a9d1e28aadf8f6f52724524df');
      const isValid = isValidXMSSAddress(address);

      expect(isValid).to.equal(true);
    });
  });

  describe('wotsPKFromSig', () => {
    it('should throw an error if the size of addr is not ADDRESS_SIZE', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const pk = getUInt8ArrayFromHex(
        'a59ee432f2fdc2fc06d51976faa43161506e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d519'
      );
      const sig = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const msg = getUInt8ArrayFromHex('3df3b0cb7f85e9196d01c9eb51f917b2b63926ac');
      const w = 256;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('990ac70f1c74a0f2d75e9dde8e06b0303e223db14d20c287c1');
      const addr = getUInt8ArrayFromHex('37f48e9a15fd');

      expect(() => wotsPKFromSig(hashFunction, pk, sig, msg, wotsParams, pubSeed, addr)).to.throw(
        'addr should be an array of size 8'
      );
    });

    it('should generate wotsPK from Sig', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const pk = getUInt8ArrayFromHex(
        '6e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d51976faa43161506e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d51976faa4316150'
      );
      const sig = getUInt8ArrayFromHex(
        'b2714448c423f8246b6ff9aa480b7a02c286425053b2714448c423f8246b6ff9aa480b7a02c286425053'
      );
      const msg = getUInt8ArrayFromHex('422bb81a5061bf90bb9a4e3df3b0cb7f85e9196d01c9eb51f917b2b63926ac0bd331f939');
      const w = 6;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '73e280e3123a762256990ac70f1c74a0f2d75e9dde8e06b0303e223db14d20c287c101f185577fe63d47dd64ba30c3'
      );
      const addr = getUInt8ArrayFromHex('37f48e9a22c915fd');
      const expectedPk = getUInt8ArrayFromHex(
        '3c46048313be496791945ce08fb0055d73b009e785661976faa43161506e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d51976faa4316150'
      );
      const expectedSig = getUInt8ArrayFromHex(
        'b2714448c423f8246b6ff9aa480b7a02c286425053b2714448c423f8246b6ff9aa480b7a02c286425053'
      );
      const expectedMsg = getUInt8ArrayFromHex(
        '422bb81a5061bf90bb9a4e3df3b0cb7f85e9196d01c9eb51f917b2b63926ac0bd331f939'
      );
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex(
        '73e280e3123a762256990ac70f1c74a0f2d75e9dde8e06b0303e223db14d20c287c101f185577fe63d47dd64ba30c3'
      );
      const expectedAddr = getUInt8ArrayFromHex('37f48e9a220a0401');
      wotsPKFromSig(hashFunction, pk, sig, msg, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('validateAuthPath', () => {
    it('should throw an error if the size of addr is invalid', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const root = getUInt8ArrayFromHex(
        'a59ee432f2fdc2fc06d51976faa43161506e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d519'
      );
      const leaf = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const leafIdx = 8;
      const authPath = getUInt8ArrayFromHex('990ac70f1c74a0f2d75e9dde8e06b0303e223db14d20c287c1');
      const n = 4;
      const h = 3;
      const pubSeed = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const addr = getUInt8ArrayFromHex('37f48e9a15fd');

      expect(() => validateAuthPath(hashFunction, root, leaf, leafIdx, authPath, n, h, pubSeed, addr)).to.throw(
        'addr should be an array of size 8'
      );
    });

    it('should validate the auth path, with root[4efa...]', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const root = getUInt8ArrayFromHex('4efa463f638d84acd09c154bd9c3730e72d9680736eac038ebda6c204e062cb08a478f');
      const leaf = getUInt8ArrayFromHex('7311d12fa38096f21c5ff3f1c6f32eea46a03abe1cdb49');
      const leafIdx = 3;
      const authPath = getUInt8ArrayFromHex('13d890ba01a01fd7a7fdb3589b99ac880c8c827cd6dfcb3c868f5c1e736bb4');
      const n = 1;
      const h = 3;
      const pubSeed = getUInt8ArrayFromHex('00dcdf1105de00a8696fe271dd0e93099a91c75d00ee');
      const addr = getUInt8ArrayFromHex('3133283e8558fa87');
      const expectedRoot = getUInt8ArrayFromHex(
        '30fa463f638d84acd09c154bd9c3730e72d9680736eac038ebda6c204e062cb08a478f'
      );
      const expectedLeaf = getUInt8ArrayFromHex('7311d12fa38096f21c5ff3f1c6f32eea46a03abe1cdb49');
      const expectedLeafIdx = 3;
      const expectedAuthPath = getUInt8ArrayFromHex('13d890ba01a01fd7a7fdb3589b99ac880c8c827cd6dfcb3c868f5c1e736bb4');
      const expectedPubSeed = getUInt8ArrayFromHex('00dcdf1105de00a8696fe271dd0e93099a91c75d00ee');
      const expectedAddr = getUInt8ArrayFromHex('3133283e85020002');
      validateAuthPath(hashFunction, root, leaf, leafIdx, authPath, n, h, pubSeed, addr);

      expect(root).to.deep.equal(expectedRoot);
      expect(leaf).to.deep.equal(expectedLeaf);
      expect(leafIdx).to.deep.equal(expectedLeafIdx);
      expect(authPath).to.deep.equal(expectedAuthPath);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should validate the auth path, with root[a59e...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const root = getUInt8ArrayFromHex(
        'a59ee432f2fdc2fc06d51976faa43161506e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d519'
      );
      const leaf = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const leafIdx = 8;
      const authPath = getUInt8ArrayFromHex('990ac70f1c74a0f2d75e9dde8e06b0303e223db14d20c287c1');
      const n = 4;
      const h = 3;
      const pubSeed = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const addr = getUInt8ArrayFromHex('37f48e9a15fd1716');
      const expectedRoot = getUInt8ArrayFromHex(
        'bbcc59adf2fdc2fc06d51976faa43161506e8845f70392cf2423b7eff8a59ee432f2fdc2fc06d519'
      );
      const expectedLeaf = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const expectedLeafIdx = 8;
      const expectedAuthPath = getUInt8ArrayFromHex('990ac70f1c74a0f2d75e9dde8e06b0303e223db14d20c287c1');
      const expectedPubSeed = getUInt8ArrayFromHex('480b7a02c286425053b2714448c423f8246b6f');
      const expectedAddr = getUInt8ArrayFromHex('37f48e9a15020102');
      validateAuthPath(hashFunction, root, leaf, leafIdx, authPath, n, h, pubSeed, addr);

      expect(root).to.deep.equal(expectedRoot);
      expect(leaf).to.deep.equal(expectedLeaf);
      expect(leafIdx).to.deep.equal(expectedLeafIdx);
      expect(authPath).to.deep.equal(expectedAuthPath);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should validate the auth path, with root[f2fd...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const root = getUInt8ArrayFromHex(
        'f2fda18d71163a7d9bf6ccc64b9d9c6b0e578829e63d170329830e8f157014f44ce80416e9fcb5b9f9210787aa'
      );
      const leaf = getUInt8ArrayFromHex('391765300c23233db115f7d3034dec404a99a2aaef0dd44bd591e8e22d812b793e');
      const leafIdx = 3;
      const authPath = getUInt8ArrayFromHex('a1051033207212fddebee14e33b1a2e634e4b3b670e2cc93691fabc7be39');
      const n = 3;
      const h = 8;
      const pubSeed = getUInt8ArrayFromHex('719b19ebcda7b6add7679553d528708abf8993d6e9314e1853a1');
      const addr = getUInt8ArrayFromHex('61f4222837f278bd');
      const expectedRoot = getUInt8ArrayFromHex(
        'f843988d71163a7d9bf6ccc64b9d9c6b0e578829e63d170329830e8f157014f44ce80416e9fcb5b9f9210787aa'
      );
      const expectedLeaf = getUInt8ArrayFromHex('391765300c23233db115f7d3034dec404a99a2aaef0dd44bd591e8e22d812b793e');
      const expectedLeafIdx = 3;
      const expectedAuthPath = getUInt8ArrayFromHex('a1051033207212fddebee14e33b1a2e634e4b3b670e2cc93691fabc7be39');
      const expectedPubSeed = getUInt8ArrayFromHex('719b19ebcda7b6add7679553d528708abf8993d6e9314e1853a1');
      const expectedAddr = getUInt8ArrayFromHex('61f4222837070002');
      validateAuthPath(hashFunction, root, leaf, leafIdx, authPath, n, h, pubSeed, addr);

      expect(root).to.deep.equal(expectedRoot);
      expect(leaf).to.deep.equal(expectedLeaf);
      expect(leafIdx).to.deep.equal(expectedLeafIdx);
      expect(authPath).to.deep.equal(expectedAuthPath);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('xmssVerifySig', () => {
    it('should verify the signature, with msg[f345...]', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const w = 6;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const msg = getUInt8ArrayFromHex('f3454cfc80dd0327d853475d86bdf9abf0304aace39a8bbcf640f6a469c508');
      const sigMsg = getUInt8ArrayFromHex(
        '8d786597b98d30a426b3a784a7459f598dfba8e33794be95164a99e58c2a414b981d444020bb74'
      );
      const pk = getUInt8ArrayFromHex('fd76a35af60f5c04057e58765e1e5525cc89c895a58f0f0a');
      const h = 5;
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedMsg = getUInt8ArrayFromHex('f3454cfc80dd0327d853475d86bdf9abf0304aace39a8bbcf640f6a469c508');
      const expectedSigMsg = getUInt8ArrayFromHex(
        '8d786597b98d30a426b3a784a7459f598dfba8e33794be95164a99e58c2a414b981d444020bb74'
      );
      const expectedPk = getUInt8ArrayFromHex('fd76a35af60f5c04057e58765e1e5525cc89c895a58f0f0a');
      xmssVerifySig(hashFunction, wotsParams, msg, sigMsg, pk, h);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(pk).to.deep.equal(expectedPk);
    });

    it('should verify the signature, with msg[5451...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const w = 16;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const msg = getUInt8ArrayFromHex(
        '5451c62c4c4b8acb6b521eacb345aae7e2f5141225f4e5c725c48b078036d1d639e7e5d11bc6a0d079d7eab06f037cf7564c51'
      );
      const sigMsg = getUInt8ArrayFromHex(
        '509096689c94a5ed9133178f218d50c166582da39c697102a666455ea56030a95fd0b677016cea28c0e12779a55192'
      );
      const pk = getUInt8ArrayFromHex('39b72ed308955b8588d7667c8bf92ee601d15e742fe958efcc68');
      const h = 3;
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedMsg = getUInt8ArrayFromHex(
        '5451c62c4c4b8acb6b521eacb345aae7e2f5141225f4e5c725c48b078036d1d639e7e5d11bc6a0d079d7eab06f037cf7564c51'
      );
      const expectedSigMsg = getUInt8ArrayFromHex(
        '509096689c94a5ed9133178f218d50c166582da39c697102a666455ea56030a95fd0b677016cea28c0e12779a55192'
      );
      const expectedPk = getUInt8ArrayFromHex('39b72ed308955b8588d7667c8bf92ee601d15e742fe958efcc68');
      xmssVerifySig(hashFunction, wotsParams, msg, sigMsg, pk, h);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(pk).to.deep.equal(expectedPk);
    });

    it('should verify the signature, with msg[3c39...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const w = 16;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const msg = getUInt8ArrayFromHex(
        '3c391e503d010c617f0f89514482e7076cb57094dce5539ae47e903be12abb82cc80a92d3dbfb3'
      );
      const sigMsg = getUInt8ArrayFromHex(
        '004501f5b0d3a0b3b59246153fe2eb76be2b5a5bb169d33b24778a3adc33818b99c256d5b2f71a9db60e512d925b9f7aec'
      );
      const pk = getUInt8ArrayFromHex('afc404fcd268b29cc828d6e9fd535ffae54cdb6d010006466a8cf4cc49adf867463aaa');
      const h = 7;
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedMsg = getUInt8ArrayFromHex(
        '3c391e503d010c617f0f89514482e7076cb57094dce5539ae47e903be12abb82cc80a92d3dbfb3'
      );
      const expectedSigMsg = getUInt8ArrayFromHex(
        '004501f5b0d3a0b3b59246153fe2eb76be2b5a5bb169d33b24778a3adc33818b99c256d5b2f71a9db60e512d925b9f7aec'
      );
      const expectedPk = getUInt8ArrayFromHex('afc404fcd268b29cc828d6e9fd535ffae54cdb6d010006466a8cf4cc49adf867463aaa');
      xmssVerifySig(hashFunction, wotsParams, msg, sigMsg, pk, h);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(pk).to.deep.equal(expectedPk);
    });
  });

  describe('verifyWithCustomWOTSParamW', () => {
    it('should throw an error if the size of extendedPk is not EXTENDED_PK_SIZE', () => {
      const message = getUInt8ArrayFromHex('7f9c9fb5566adb75cc196a272fb9650e7b546f2c9640');
      const signature = getUInt8ArrayFromHex(
        '512a84189bdcba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b7463280240'
      );
      const extendedPk = getUInt8ArrayFromHex(
        '296842557a47844348593ef6a5a6ea16a65caf46bdd3451fc6368d5bafc280a2b840036f2775a9967a13be23eb0bc2ce5937aceb3dc4379822aace'
      );
      const wotsParamW = 256;

      expect(() => verifyWithCustomWOTSParamW(message, signature, extendedPk, wotsParamW)).to.throw(
        `extendedPK should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`
      );
    });

    it('should throw an error if the signature type is not valid', () => {
      const message = getUInt8ArrayFromHex('773415aad8e6517f9c9fb5566adb75cc196a272fb9650e7b546f2c9640');
      const signature = getUInt8ArrayFromHex(
        '0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620'
      );
      const extendedPk = getUInt8ArrayFromHex(
        '0b88283fc2296842557a47844348593ef6a5a6ea16a65caf46bdd3451fc6368d5bafc280a2b840036f2775a9967a13be23eb0bc2ce5937aceb3dc4379822aace72e0d3'
      );
      const wotsParamW = 256;

      expect(() => verifyWithCustomWOTSParamW(message, signature, extendedPk, wotsParamW)).to.throw(
        'Invalid signature type'
      );
    });

    it('should verify with custom wots paramW, with message[7734...] signature[0d40...]', () => {
      const message = getUInt8ArrayFromHex('773415aad8e6517f9c9fb5566adb75cc196a272fb9650e7b546f2c9640');
      const signature = getUInt8ArrayFromHex(
        '0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c74632802405e1d6c6717e063281d6c6717e0632802405e1d6c67632802405e1d6c6717e0ebba931b74632802405e1d6c'
      );
      const extendedPk = getUInt8ArrayFromHex(
        '1388283fc2296842557a47844348593ef6a5a6ea16a65caf46bdd3451fc6368d5bafc280a2b840036f2775a9967a13be23eb0bc2ce5937aceb3dc4379822aace72e0d3'
      );
      const wotsParamW = 256;
      const expectedMessage = getUInt8ArrayFromHex('773415aad8e6517f9c9fb5566adb75cc196a272fb9650e7b546f2c9640');
      const expectedSignature = getUInt8ArrayFromHex(
        '0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c74632802405e1d6c74632802405e1d6c6717e063281d6c6717e0632802405e1d6c67632802405e1d6c6717e0ebba931b74632802405e1d6c'
      );
      const expectedExtendedPk = getUInt8ArrayFromHex(
        '1388283fc2296842557a47844348593ef6a5a6ea16a65caf46bdd3451fc6368d5bafc280a2b840036f2775a9967a13be23eb0bc2ce5937aceb3dc4379822aace72e0d3'
      );
      const expectedResult = false;
      const result = verifyWithCustomWOTSParamW(message, signature, extendedPk, wotsParamW);

      expect(message).to.deep.equal(expectedMessage);
      expect(signature).to.deep.equal(expectedSignature);
      expect(extendedPk).to.deep.equal(expectedExtendedPk);
      expect(result).to.deep.equal(expectedResult);
    });
  });

  describe('verify', () => {
    it('should throw an error if the size of extendedPk is not EXTENDED_PK_SIZE', () => {
      const message = getUInt8ArrayFromHex('7f9c9fb5566adb75cc196a272fb9650e7b546f2c9640');
      const signature = getUInt8ArrayFromHex(
        '512a84189bdcba931b74632802405e1d6c74632802405e1d6c6717e0ebba931b74632802405e1d6c0d4025d8143ce620eceea7cd8b512a84189bdc82ef6717e0ebba931b74632802405e1d6c6717e0ebba931b7463280240'
      );
      const extendedPk = getUInt8ArrayFromHex(
        '296842557a47844348593ef6a5a6ea16a65caf46bdd3451fc6368d5bafc280a2b840036f2775a9967a13be23eb0bc2ce5937aceb3dc4379822aace'
      );

      expect(() => verify(message, signature, extendedPk)).to.throw(
        `extendedPK should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`
      );
    });

    it('should verify, with message[] signature[]', () => {
      const message = getUInt8ArrayFromHex(
        '18cfbf557c71fb56a0fa58eda3c4484dd703a0d0706362e62fe3d6a9d54412533fc47dcf2ec87250bb23533fa81c8126846c692fe287b6ede747d02df70e47'
      );
      const signature = getUInt8ArrayFromHex(
        '340f3dc6bf93249e805d3751a63a27d50b50b8388ae119ef2a42f66276e8c397f84be06670362fb62f1f43de43f2304324be54e53d44dcda6cf123b7299db37573819f5b7b77b0b5c379824a201c6cf71f8389bda9a92a72b3d932a2572746f0c412f03b0b53b3006222104313fce9aba1446153733128da3c42127662a094474efd9870109658f2f7c241943e90894677ecd0e724701385f4c9bce0acd30dc94e436eee4686ce8b79d520456cd947e0e27331e4bc59abfb4099b1430e9ff814401ba9e62e321b9634d32f24968610e3b0b98f809cbdc122752f4ea53435660eb0ac8c5c06d6f0095095b86e069c2794466c173304ed4a52c4df2e4be5df0d31686cf6bfe29c13c582e0baadd493e13bfaef55de09addbad9c034a74bd7ae739ce7c4edc16e146babe52aeebf7a3c557807cb4be3f173d6838fb2bbd70e1f2b1fa16ee45a43ca79bf5502d7ccab063507596cef3acb1f4ef7eeaf6e26985bb90944c9500a2084642025e582baca2f051099a1a6be99ac75b0db23adb186bc1969bc206081ef24883307b8a0385e4dd89060457361c98f67559d0903452a4595d903229792573f1d86410588249783ba4c7c339985bf15870cfd0142503b26238cf7294241ce5aff3e955b18b2e984ea556814496c47a42f45b862ca89e179c30092df6c497c798e34a533dccbdc6520867ec5f24bb916e721a45ebb79fcb121eaf888e7d5c5c54e01f075c5adefb8e7710f18f8ca37c9c6e1ed6703c6be06a9503ab7486fadd68b4b89560bb5e808c3f16b00d679df8f3406518c822f00103c2820e65590ba0299e523e1a6f4f4f44e4324acfe59175bb740685d37fc2824513e09f451ef81f90e9623b725548a1a3cce0efd3f3648c3596c901cdeccd30c1d9bdde45fd96e25137d25cf93b79dac4db5e0e509d4697f2ac9701100defd9518ffa07d2a4a0106da21c9510de0397e2acf0890f9893961d95b397fc39ae7b4d8a82b032e5284a7c17316a9fddd63fac7336e86b3a666d0055978a7c2858c3a42bc9bdec16745e7d9dc2f788ea0d81c14b9f23e380339f1fe2f35c294996cf8db795d67868b7a202628cf8df59dd92bd60f15b64bcb3961977e76e191ebfce27973d3237617f36cac11368694f68416be1a8b772cdc27c569996fb5f5fac59b58096983178ec510f72508a746074577fc4ea8f6f143ed5a868642b4e4dee26f6fcdb396d614f6167f61cdd666a4e331deb3f5f67f1e9a51f99fd50ba2cdfb93023275523c47a91d92d3a4cd6976636904e628e15e72ed284d9b5cf1ea4e1f816a399f3eed15c6ad67f6d485d1bd256b6385450e05573c5555f0dcaf877c081ef8b04362f9b1e74efd8b1f0e3f86d1a45ae1a40bebef1eead69da9f226799038880510779f6f531b41b97169d5d2917d6e418318655bf4379c76cc08cb1632e780d55291c9532a35ad39b9a7fdf90e8a4f2ab1776b87dc330ab23a8584758525314216b1abf841364f0a381f2f2e0c8cffc8e0d8a3b988ce17f91e0d2d06a3bbeb46fdaf4d635e3fd6e34f719fa69cf3ce15eb17100c1e8f3d56713659d2c59f3e0f1da5e4694bed48251acfc609e46d179e6d92a0c5a86a8b361ea8f8f9c4d60fa170b32d806c7510805dbe5f4b3e1ddcea3e58537597264dbc94d1a189183435c48ce2c4fa2e744944933f5613c2fd28a63d750ea684ae5eea49628fdbacfa6ae31ddbd48eca3b779c36e559e69bf5927073b4904c9d7fd92e3ed89474db99e0dbe5ef449d35124353a0aa72ab97822751b5514d53eea8fcaaf457a233b99bd26d80fac4e4fe590f04081a04ee4fcab9a5167ad0e53af61aa60a386aa90504b1a36a241f8dd63513f1adeeaa0a9adc703182569ef7a4adba1b94498855e582155a89ac8d26ee0e1c9da28839c429332d64281736e9ce2077b26204e0163807597c7ed16105bd30e7a9f785061ef4f3429a67ac43af76c3d4cb3c04f3c28bba4cf9400cfe9f0a11ec04b46b4006e89f68182c812878dbe512815e7e835761d0c45fd2e4505a940974cd40c2cc3d0bb4059f60faf212ada0762d350d9b65bf8f1dcabc3d45a665604c7326ca3f95c21d380ceacd78007029b2a01872ab2510ba7634b6726c2e661758cb843331b807814bf419dcf452401c33cf91901287e0d14117e71058aa346baeaf7a79f053db4ca5cbf9622a81601258951536be2adee17a6567927138bed082547efb6de3d06990bfc7f842733ca4c6e1be32301f980686ad649942a7f0eb490bfb34d96a02d0a639cd61d0487283721b0e8cbc2f1458c2edb5301e5602bd6055fc92368bd6241a020d411f27476a4eda27e78030438b1e6e56d9a15adbfde4a6a895357f097502e7a10a13c18916a788907501886f8f00cc4f78d16576e9d886bf3484f85cbf4f141c18f240b03a7fd7f7e37ee15e7a5ea45040507515c67de1e5557160586d84e52d69fb759eee024da852eab4dc611473211ea30dfa72eef6f4594d4eff2d32c941806a3e2d5670fe3b9e2e5f0ba66cb55dc9af3f52270909f01e09f8f6a371763e1a282a5ba7269cf68df80a2a8cb8bef21232e57ed72913055ca4eb5d0de53ae2dce5164f7113965519f0939058ccd648c374dd42e080b9860da2edc66e8c5a09ac09a098ea36b8684857d28894e34177d57812069463bf2ccee080c40fc0cef7c34a46c1c437385c62dd948ab1a9bea3f88fac7f065e045813cb1ca6e9a7980208370b97196f42d41f30a72bf88090e18120d8a4bb995cae60036794d2f3f6058708f62922f5fb7c249090559e9228163eaf78ec85320c8e78dc5ebd34d8a8917becaca278cea548e25bb62140b408710c9d9c80ef6474c478ab6036483e2ba6f6d01e42be54afcfd37ce229ba54a96e00a177605a71c873cc39cbfa21106e0acc28c6fbdb073b0b6f7ad03ec514ef79b897bf60c18a48a0d49ca865211351341cd396a873d271f27f0ed765b5ddb210be04ab2402e8d7eda412d7ab72326d5230c3f9a63c506d6f40fe02c8a375737325a384d6e958ee175b3f99bc3f774c8c23aecc8a61ff22a5856412b31638bc1367d5d0743f3fb21b7719512895e1194a00c18cf7d6338e399af7c35be0eb359f1e29b43a8f123e6e28ed86c1865dfd47a1afc2cdca2b3442d1de9003f1012734b9c76'
      );
      const extendedPk = getUInt8ArrayFromHex(
        '133956a232cf2decbef7722ee12168a5b4a8d41e5baccb5777540dd31c168a75c534bcb09b5707b76829a414de6d77ecf80c8fc371da7cbe6075daa289e5327557daf9'
      );
      const expectedResult = false;
      const result = verify(message, signature, extendedPk);

      expect(result).to.equal(expectedResult);
    });
  });
});

describe('Additional test cases for [xmss]', function testFunction() {
  this.timeout(0);

  it('TestXMSSGetAddress', () => {
    const [height] = [getUInt8ArrayFromHex('04')];

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);

    const address = xmss.getAddress();
    const encodedAddress = Array.from(address, (byte) => byte.toString(16).padStart(2, '0')).join('');
    const expectedAddress = '11020013b5158e1e45d28c5c2dee4abfaf7e4ebf';

    expect(encodedAddress).to.equal(expectedAddress);
  });

  it('TestIsValidXMSSAddress', () => {
    const [height] = [getUInt8ArrayFromHex('04')];

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);

    const address = xmss.getAddress();

    expect(isValidXMSSAddress(address)).to.equal(true);
  });

  it('TestIsValidXMSSAddress2', () => {
    const addrStr = '2001430a5152fcc369c309caf3554bd3528161c8';
    const addr = [];
    for (let c = 0; c < addrStr.length; c += 2) {
      addr.push(parseInt(addrStr.substring(c, c + 2), 16));
    }
    const address = new Uint8Array(20);

    for (
      let addressIndex = 0, addrIndex = 0;
      addressIndex < address.length && addrIndex < addr.length;
      addressIndex++, addrIndex++
    ) {
      address.set([addr[addrIndex]], addressIndex);
    }

    expect(isValidXMSSAddress(address)).to.equal(false);
  });

  it('TestXMSSGetMnemonic', () => {
    const [height] = [getUInt8ArrayFromHex('04')];

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);

    const expectedMnemonic =
      'ban bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback';
    const mnemonic = xmss.getMnemonic();

    expect(mnemonic).to.equal(expectedMnemonic);
  });

  it('TestXMSSGetExtendedSeed', () => {
    const [height] = [getUInt8ArrayFromHex('04')];

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);

    const expectedESeed =
      '110200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
    const eSeed = xmss.getExtendedSeed();
    const eSeedStr = Array.from(eSeed, (byte) => byte.toString(16).padStart(2, '0')).join('');

    expect(eSeedStr).to.equal(expectedESeed);
  });

  it('TestXMSSCreationHeight4', () => {
    const [height] = [getUInt8ArrayFromHex('04')];

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);

    const expectedAddress = '11020013b5158e1e45d28c5c2dee4abfaf7e4ebf';
    const expectedPK =
      '110200c25188b585f731c128e2b457069e' +
      'afd1e3fa3961605af8c58a1aec4d82ac' +
      '316d3191da3442686282b3d5160f25cf' +
      '162a517fd2131f83fbf2698a58f9c46a' +
      'fc5d';

    const pk = xmss.getPK();
    const encodedPk = Array.from(pk, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(encodedPk).to.equal(expectedPK);

    const address = xmss.getAddress();
    const encodedAddress = Array.from(address, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(encodedAddress).to.equal(expectedAddress);

    const tmpAddr = getXMSSAddressFromPK(pk);
    const encodedTmpAddr = Array.from(tmpAddr, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(encodedTmpAddr).to.equal(expectedAddress);

    const desc = newQRLDescriptorFromExtendedPk(pk);
    expect(desc.getHeight()).to.equal(4);
    expect(desc.getHashFunction()).to.equal(HASH_FUNCTION.SHAKE_128);
  });

  it('TestXMSSCreationHeight6', () => {
    const [height] = [getUInt8ArrayFromHex('06')];

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);

    const expectedAddress = '11030084aa70bdb5f610cd0d75c9ae1b86606885';
    const expectedPK =
      '110300859060f15adc3825adeec85c7483' +
      'd868e898bc5117d0cff04ab1343916d4' +
      '07af3191da3442686282b3d5160f25cf' +
      '162a517fd2131f83fbf2698a58f9c46a' +
      'fc5d';

    const pk = xmss.getPK();
    const encodedPk = Array.from(pk, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(encodedPk).to.equal(expectedPK);

    const address = xmss.getAddress();
    const encodedAddress = Array.from(address, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(encodedAddress).to.equal(expectedAddress);

    const tmpAddr = getXMSSAddressFromPK(pk);
    const encodedTmpAddr = Array.from(tmpAddr, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(encodedTmpAddr).to.equal(expectedAddress);

    const desc = newQRLDescriptorFromExtendedPk(pk);
    expect(desc.getHeight()).to.equal(6);
    expect(desc.getHashFunction()).to.equal(HASH_FUNCTION.SHAKE_128);
  });

  it('TestXMSS', () => {
    const [height] = getUInt8ArrayFromHex('04');

    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X);
    expect(xmss).to.not.be.equal(null);
    expect(xmss.getHeight()).to.equal(height);

    const message = new Uint8Array(32);
    const { sigMsg: signature, error } = xmss.sign(message);
    expect(error).to.equal(null);

    for (let i = 0; i < 1000; i++) {
      expect(verify(message, signature, xmss.getPK())).to.equal(true);
    }

    signature[100] += 1;
    expect(verify(message, signature, xmss.getPK())).to.equal(false);

    signature[100] -= 1;
    expect(verify(message, signature, xmss.getPK())).to.equal(true);

    message[2] += 1;
    expect(verify(message, signature, xmss.getPK())).to.equal(false);

    message[2] -= 1;
    expect(verify(message, signature, xmss.getPK())).to.equal(true);
  });

  it('TestXMSSExceptionConstructor', () => {
    const height = new Uint8Array(7);
    const seed = new Uint8Array(COMMON.SEED_SIZE);

    expect(() => newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, COMMON.SHA256_2X)).to.throw(
      'For BDS traversal, H - K must be even, with H > K >= 2!'
    );
  });

  it('TestXMSSExceptionVerify', () => {
    const message = new Uint8Array(COMMON.SEED_SIZE);
    const signature = new Uint8Array(2287);
    const pk = new Uint8Array(CONSTANTS.EXTENDED_PK_SIZE);

    expect(() => verify(message, signature, pk)).to.throw('Invalid signature type');
  });

  it('TestXMSSExceptionVerify2', () => {
    const message = new Uint8Array(COMMON.SEED_SIZE);
    const signature = new Uint8Array(2287);
    const pk = new Uint8Array(CONSTANTS.EXTENDED_PK_SIZE);
    pk[0] = new Uint8Array([COMMON.XMSS_SIG])[0] << 4;

    expect(() => verify(message, signature, pk)).to.throw('Invalid signature size');
  });

  it('TestXMSSChangeIndexTooHigh', () => {
    const [height] = [getUInt8ArrayFromHex('04')];
    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, 16);

    expect(() => xmss.setIndex(20)).to.throw('Index too high');
  });

  it('TestXMSSChangeIndexHigh', () => {
    const [height] = [getUInt8ArrayFromHex('04')];
    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, 16);

    expect(() => xmss.setIndex(16)).to.throw('Index too high');
  });

  it('TestXMSSChangeIndexLimit', () => {
    const [height] = [getUInt8ArrayFromHex('04')];
    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, 16);
    xmss.setIndex(15);
    const index = xmss.getIndex();

    expect(index).to.equal(15);
  });

  it('TestXMSSChangeIndex', () => {
    const [height] = [getUInt8ArrayFromHex('04')];
    const seed = new Uint8Array(COMMON.SEED_SIZE);
    const xmss = newXMSSFromSeed(seed, height, HASH_FUNCTION.SHAKE_128, 16);
    xmss.setIndex(0);
    const index = xmss.getIndex();

    expect(index).to.equal(0);
  });
});
