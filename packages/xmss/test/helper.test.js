import { expect } from 'chai';
import { describe, it } from 'mocha';
import { COMMON, ENDIAN } from '../src/constants.js';
import {
  addrToByte,
  binToMnemonic,
  extendedSeedBinToMnemonic,
  mnemonicToBin,
  mnemonicToExtendedSeedBin,
  mnemonicToSeedBin,
  seedBinToMnemonic,
  setChainAddr,
  setHashAddr,
  setKeyAndMask,
  setLTreeAddr,
  setOTSAddr,
  setTreeHeight,
  setTreeIndex,
  setType,
  sha256,
  shake128,
  shake256,
} from '../src/helper.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './utility/testUtility.js';

describe('Test cases for [helper]', () => {
  describe('shake128', () => {
    it('should return the SHAKE128 hash of type Uint8Array', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      out = shake128(out, message);

      expect(out).to.be.an.instanceOf(Uint8Array);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[12] and out[15]', () => {
      const message = new Uint8Array(12);
      message[3] = 6;
      message[9] = 8;
      let out = new Uint8Array(15);
      out[0] = 1;
      out[7] = 2;
      const expectedShake128Out = getUInt8ArrayFromHex('72cc5782d8c090e3d22571370fe85c');
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[12] and out[6]', () => {
      const message = new Uint8Array(12);
      message[1] = 3;
      message[11] = 9;
      let out = new Uint8Array(6);
      out[0] = 7;
      out[3] = 12;
      const expectedShake128Out = getUInt8ArrayFromHex('3ec611909104');
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[30] and out[42]', () => {
      const message = new Uint8Array(30);
      message[13] = 17;
      let out = new Uint8Array(42);
      out[32] = 1;
      out[11] = 6;
      const expectedShake128Out = getUInt8ArrayFromHex(
        '3595556054acb196d7aaa3f36c72d2817e4cb286010b501211987629433484f3e04298f6cec3a7327855'
      );
      out = shake128(out, message);

      expect(out).to.deep.equal(expectedShake128Out);
    });

    it('should return the SHAKE128 hashed Uint8Array with message[00000...] and out[0103...]', () => {
      const message = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000000000000000000000000000000000d16620155e581434753fee01e9e4ce59b0e58b5194db20efae3164686df9751101ceeaa53f44f6dd4c59348d87381c36dd5373f3077a804c321246fcf8c2cfbe'
      );
      let out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      out = shake128(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        '6e2c52f50c80e47508884b3604feb7d3aa1854e63f3c9d5d071542700536357ecc22da1306b7fd9a6a5f8c97f9dff11b0d5282a1fa2e6c7b'
      );

      expect(out).to.deep.equal(expectedSha256Out);
    });
  });

  describe('shake256', () => {
    it('should return the SHAKE256 hash of type Uint8Array', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      out = shake256(out, message);

      expect(out).to.be.an.instanceOf(Uint8Array);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[48] and out[18]', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      const expectedShake256Out = getUInt8ArrayFromHex('eda313c95591a023a5b37f361c07a5753a92');
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[12] and out[6]', () => {
      const message = new Uint8Array(12);
      message[0] = 5;
      let out = new Uint8Array(6);
      out[0] = 3;
      const expectedShake256Out = getUInt8ArrayFromHex('775e667edbb4');
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[54] and out[15]', () => {
      const message = new Uint8Array(54);
      message[5] = 7;
      let out = new Uint8Array(15);
      out[3] = 12;
      const expectedShake256Out = getUInt8ArrayFromHex('ce507263c3b9a7cef865a35f671d97');
      out = shake256(out, message);

      expect(out).to.deep.equal(expectedShake256Out);
    });

    it('should return the SHAKE256 hashed Uint8Array with message[96] and out[56]', () => {
      const message = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000000000000000000000000000000000aba13b521fd94df15e319b27d676508518355d418ef2a67562cb44bd8368cb8032bc35b54d4abdcc8781ffafce9e06d750d80790b3fd3c9fd4212f885e0ece7f'
      );
      let out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      out = shake256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        'bdb435c86b28924873d965dfa87b3d59a2e7ee5d594eedfc276e2f99f995fcab13752d7d6351961dd135166b013fd7e1963c24a65165fc1e'
      );

      expect(out).to.deep.equal(expectedSha256Out);
    });
  });

  describe('sha256', () => {
    it('should return the SHA256 hash of type Uint8Array', () => {
      const message = new Uint8Array(48);
      let out = new Uint8Array(18);
      out = sha256(out, message);

      expect(out).to.be.an.instanceOf(Uint8Array);
    });

    it('should return the SHA256 hashed Uint8Array with message[23] and out[16]', () => {
      const message = new Uint8Array(23);
      message[13] = 17;
      let out = new Uint8Array(16);
      out[7] = 8;
      out[11] = 6;
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex('944e4d18b7add881cda9481934e8293e');

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[30] and out[30]', () => {
      const message = new Uint8Array(30);
      message[1] = 8;
      message[8] = 1;
      let out = new Uint8Array(30);
      out[29] = 32;
      out[8] = 4;
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex('59556489c4bdc542c319eb123673493abec0d4cd25476cb64c06d161a47f');

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[4] and out[18]', () => {
      const message = new Uint8Array(4);
      message[1] = 6;
      message[2] = 4;
      message[3] = 2;
      let out = new Uint8Array(18);
      out[16] = 3;
      out[8] = 17;
      out[4] = 13;
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex('26ee19ac2a2627552adad15327fe052c0360');

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[0000...] and out[0000...]', () => {
      const message = getUInt8ArrayFromHex(
        '000000000000000000000000000000000000000000000000000000000000000304050301030202070304050708040503010302020703040507080405030103020000000400000003000000020000000200000007000000030000000200000000'
      );
      let out = getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000');
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        'cfd283314d47fec74a7e37a095a8287aafa602835babf18ea460c2211c2fe978'
      );

      expect(out).to.deep.equal(expectedSha256Out);
    });

    it('should return the SHA256 hashed Uint8Array with message[0000...] and out[0103...]', () => {
      const message = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000000000000000000000000000000000cfd283314d47fec74a7e37a095a8287aafa602835babf18ea460c2211c2fe978a6fd69e201c31876b491728d0908e25a23ac97c31205d98fd0796e944cea10f9'
      );
      let out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      out = sha256(out, message);
      const expectedSha256Out = getUInt8ArrayFromHex(
        '535b1a6f45bdd4796c7db5a811f111e6387f2f39a36f18c42fde67fbd4eff9ca030501020702070303050102070207030305010207020703'
      );

      expect(out).to.deep.equal(expectedSha256Out);
    });
  });

  describe('setType', () => {
    it('should set the type from index 3 till 7, with typeValue 1', () => {
      const addr = getUInt32ArrayFromHex('0000000900000009000000020000000300000009000000010000000000000005');
      const typeValue = getUInt32ArrayFromHex('00000001')[0];
      setType(addr, typeValue);
      const expectedAddr = getUInt32ArrayFromHex('0000000900000009000000020000000100000000000000000000000000000000');

      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should set the type from index 3 till 7, with typeValue 2', () => {
      const addr = getUInt32ArrayFromHex('0000000200000003000000050000000700000004000000090000000100000000');
      const typeValue = getUInt32ArrayFromHex('00000002')[0];
      setType(addr, typeValue);
      const expectedAddr = getUInt32ArrayFromHex('0000000200000003000000050000000200000000000000000000000000000000');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setLTreeAddr', () => {
    it('should set the lTree at index 4', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const lTree = getUInt32ArrayFromHex('00000014')[0];
      setLTreeAddr(addr, lTree);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000001400000005000000060000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setOTSAddr', () => {
    it('should set the ots at index 4', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const ots = getUInt32ArrayFromHex('00000014')[0];
      setOTSAddr(addr, ots);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000001400000005000000060000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setChainAddr', () => {
    it('should set the chain at index 5', () => {
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      const chain = getUInt32ArrayFromHex('00000010')[0];
      setChainAddr(addr, chain);
      const expectedAddr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000100000000700000008');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setHashAddr', () => {
    it('should set the hash at index 6', () => {
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      const hash = getUInt32ArrayFromHex('00000016')[0];
      setHashAddr(addr, hash);
      const expectedAddr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000001600000008');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setKeyAndMask', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      const keyAndMask = getUInt32ArrayFromHex('00000011')[0];
      setKeyAndMask(addr, keyAndMask);
      const expectedAddr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000011');

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setTreeHeight', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const treeHeight = getUInt32ArrayFromHex('00000014')[0];
      setTreeHeight(addr, treeHeight);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000000400000014000000060000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('setTreeIndex', () => {
    it('should set the keyAndMask at index 7', () => {
      const addr = getUInt32ArrayFromHex('000000000000000100000002000000030000000400000005000000060000000700000008');
      const treeIndex = getUInt32ArrayFromHex('00000012')[0];
      setTreeIndex(addr, treeIndex);
      const expectedAddr = getUInt32ArrayFromHex(
        '000000000000000100000002000000030000000400000005000000120000000700000008'
      );

      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('addrToByte', () => {
    it('should add addr to bytes in case of little endian', () => {
      const getEndianFunc = () => ENDIAN.LITTLE;
      const bytes = new Uint8Array(32);
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = getUInt8ArrayFromHex(
        '0000000100000002000000030000000400000005000000060000000700000008'
      );

      expect(bytes).to.deep.equal(expectedUint8Array);
    });

    it('should add addr to bytes in case of big endian', () => {
      const getEndianFunc = () => ENDIAN.BIG;
      const bytes = new Uint8Array(32);
      const addr = getUInt32ArrayFromHex('0000000100000002000000030000000400000005000000060000000700000008');
      addrToByte(bytes, addr, getEndianFunc);
      const expectedUint8Array = getUInt8ArrayFromHex(
        '0100000002000000030000000400000005000000060000000700000008000000'
      );

      expect(bytes).to.deep.equal(expectedUint8Array);
    });
  });

  describe('binToMnemonic', () => {
    it('should generate mnemonic from binary, with input length [3]', () => {
      const input = getUInt8ArrayFromHex('38ff00');
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic = 'deed utmost';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [12]', () => {
      const input = getUInt8ArrayFromHex('8e38cb57812de6b2422270ff');
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic = 'modern mind friar bath tomb carbon calf bad';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [30]', () => {
      const input = getUInt8ArrayFromHex('48bd21ff802fa3d43663ee438c54d203b07a5bc82c9bdb3c8311f36555c4');
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'essex spin zero adopt pill early hail throng mile fast afloat amen gene louvre orphan regret lower build harry genus';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input length [300]', () => {
      const input = getUInt8ArrayFromHex(
        '7c53d80b63cd249443ffc0513087b306e58ec84a5b3575faa820c96dcfd7bb80a35d4226ddbe2cae0d39b6f378935f41afea276c1b8d4dd205c757e16af021aa36830ec245899666ced354bd79fba231b90738e667da70b72a9f4c14f89b25dba41ee460cc43e97bc60a8647c06f1bf5a057c876af378f4ed968fc1f8ad173f142bc2b97b062a938e70d69be20da8256ff4695c109ed6ab92dde5823d1ab14f039995bf2ad41cb6e8bd94cb33684e207b461ca309273fb50c3197f44d69e29b368fd5c9323a2bb7215ec3ba863cd53d432779049fa8a3fc554b01df06eac29d760ba1c99cb3391dc26c97e3ebc74e14a9d8b1ef33d865dcc33e557af0cf76dc224dd31be66e74e92c656b328d77da346c81c9c864dee3a95cf41ba67f97183a920df32d24aa08906c151ae6cfa7e5f17d435a18c07da6f2f98ed52ce25bd0df27c44c99f31ab5ab421e7907526de3bcd4a91bc67fa30a315f361898102b023c67853db2acc3986b946d50eac8d1fc0629d27f641dc6acf0d965db82ff24ba90cc534e27c6fe6'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'ledge dispel arrow dingus carnal eddy zipper airy cosmic layer aloof fully signal plate curse grab pony assist icon wreck rudder arcane glance cakile tace thesis quay square rhine david naples virus raid petty hound rival feat burma shrine lewis hold active price held await career meet havoc sold curl saga paste peru bovine altar module hedge poem rhyme prefer fairly fierce oracle glib pin unkind great shabby treaty rust area hammer scent venom walk alert silken hold david volley stunt mortal bull purely jest beet runway robust range clammy deduce insert hidden than sullen casual zaire hero screen parcel hoard mystic talent lose spend rave vacuum oily genius clasp duel rhexia middle nephew refer helium than layman grit picket mutton draft firm cousin limp fate pair orange herb steel namely demo ruby buyer turf rosa had static stair chart mostly past mental woods follow acre valet trot cider just roll sit sleeve deeply swear human liar tundra joy beige pack real view street glide sent tight lawn ate kernel seed feat cover tokyo topaz trauma shiver holy chilly knack pier hull brave silk fed those nimble virus root linger invade depart bust vienna spinus prefix mean hound flank tonal win tip blast earl pencil school suite victim ocean state socket geneva auntie check eerily omega cove resign relief brush motion flew take sacred exit bowl hefty picket picnic gosh grim nylon adjust actual shoe magnet super punk defy hopple energy first pump spiky scent cider cheer haiti sweep puppy auburn hasty rinse your facial mourn sharp feel left year';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('seedBinToMnemonic', () => {
    it('should generate mnemonic from binary, with input[216, 6...]', () => {
      const input = getUInt8ArrayFromHex(
        'd806cbcdb829b5be1a354311bae3f8cef4adce0f10e47a2268acc80074bc89d972e86badab52cfe5f891e064041548d9'
      );
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'strap humble snug loudly resin tera curl could rotten dower solely expect social vast thug person hemp smart abode factor melt note toxin rotor proper clutch tip meant tehran dread bend mite';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[68, 138...]', () => {
      const input = getUInt8ArrayFromHex(
        '448a88928517c812db0e629262b3fb610ff9ae933cb6a327e6daa202a94eaf75b61834ece6759d0554c3832f20cf6d05'
      );
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'edit popery mutual flair sight coffee avail choose guess draft greek zigzag quilt crop revive crater tone pretty adhere nest radar gave blink ferry told gag albeit falcon lowest verbal son soul';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[10, 200...]', () => {
      const input = getUInt8ArrayFromHex(
        '0ac8bbebfc17e6300c4a5024e71ea44b6ac879146a7631314617b8dd02e0bb015ef6656b4e52a885d573f57d6844de54'
      );
      const mnemonic = seedBinToMnemonic(input);
      const expectedMnemonic =
        'arm midas tunic seam toast abra exempt acute tool tried eyed pump lady enamel karate bay embark leaf sword coke rough bestow warp frail fell claim male freer wait stiff effect tiger';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('extendedSeedBinToMnemonic', () => {
    it('should generate mnemonic from binary, with input[51, 195...]', () => {
      const input = getUInt8ArrayFromHex(
        '33c3c2f97a4d96517e3d06c3787a5cdc66ab4db93f3f7b58858b4c1b6b1a36918fe93a69bab1d3bf1b858e5436a8cd546e5ccb'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'crop diary wholly pivot noisy blaze dire house koran play sweep hoard fauna near dove resent main renal bound react dallas blunt travel plump rosy brew satin ripen modify early port statue ignore smell';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[61, 200...]', () => {
      const input = getUInt8ArrayFromHex(
        '3dc8184fe018bf358c0d5480b54214a2cd5cce59d8f761553e40347948cc57404eb00c0c50a29ad99a220d6603238666f2d38d'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'divine lone file ache saturn fulfil attach equip repine buy photo steel sodium pack weary bended dole aerial lake mine freeze aim rain scotch finish chrome submit person attain grass cane havoc vicar decree';

      expect(mnemonic).to.equal(expectedMnemonic);
    });

    it('should generate mnemonic from binary, with input[155, 172...]', () => {
      const input = getUInt8ArrayFromHex(
        '9bac999fd10b120f85982ceee0e2bbae1519a609ee1dc9df7da1d0f3b8c6bd590ad7e6eb362092ccf2d9f4ce0f78ae77ca7f95'
      );
      const mnemonic = binToMnemonic(input);
      const expectedMnemonic =
        'orient sit pastor ballad barrel what oak sole tenant climb quebec flame plead pardon brink paid let bred viola milk safer mould strait import dad anti smite cocoa voice tend kuwait torch slab who';

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  describe('mnemonicToBin', () => {
    it('should throw an error if the word count is not even', () => {
      const mnemonic = 'latch supply taxi';

      expect(() => mnemonicToBin(mnemonic)).to.throw(`Word count = ${mnemonic.split(' ').length} must be even`);
    });

    it('should throw an error if the word is invalid or does not exist in word list', () => {
      const mnemonic = 'quantum design';

      expect(() => mnemonicToBin(mnemonic)).to.throw('Invalid word in mnemonic');
    });

    it('should generate binary from mnemonic, with valid 2 words', () => {
      const mnemonic = 'italy india';
      const binary = mnemonicToBin(mnemonic);
      const expectedBinary = getUInt8ArrayFromHex('72b6f3');

      expect(binary).to.deep.equal(expectedBinary);
    });

    it('should generate binary from mnemonic, with valid 254 words', () => {
      const mnemonic =
        'easel within gallop caught severe pizza stern rear awful shame bend suez chalet ankle shock drool engage jacob guest hardly driver pit iron gong gaucho pile room carbon genius idiom eater utter grab cheat lawful koran rife lid sirius shyly otter naval magic moth proper crypt object swap caesar fabric steak monday warsaw artist group rob sonic binary her mud useful scout vase week debt rule waiter safer figure nurse india did timber viral punish shrub ripple lamp glib world mosque bulb demand friday short hazel draw slater weight twelve knit sudden barber edict cost energy mentor gothic belt dispel rarely scotch real surf let cat fiery above audio panel beat never spirit pedal export poland hour zero olive grid permit recess ever elicit amend stop cyclic denial sword haste akin ploy brink murky join would order sponge age naples cast carpet pine stot pride track sentry torch grin shawl smelly wedge maya expect via noun sudan sweat logic bush help crazy risk item stark malt libel jockey spite chunk audit simian altar spout kick camera buyer mutual flame always stiff mainly envoy stroll branch data trial soften rosy doubt bent rugby worm kiss again throw other war employ adobe andrew expose burnt spinus parish pillow retire franc spill fuzzy aloud canvas gentle tame day wine ivan tax khowar vague sorry greasy geneva before eric goose soothe stamp motive serene teeth locate solo bran obese pink moor ring gravel misty later intend vision whisky mary sinful comedy lunch seize summer plaguy wren danger campus';
      const binary = mnemonicToBin(mnemonic);
      const expectedBinary = getUInt8ArrayFromHex(
        '43afb95a525bc41a4fd64b220f3c4e154da226b08dc6641146e73262c651410a4a7225ee5b2a3cba52425bf6e0441f015fa27b7ae787b7c7e8c97c7c9c193c851905ab5349987dbf21f4b7d598edf670bb623b92cfa16e68d916efdc0df0ff7a385bbcf58bd54fd9806f33c5e5af3eacbc77b867975dbfcb9011f43a0579c6b66c402caff7deca782da011744730a46d8a45f71523d8b0bc0cb1edb97da2574f900b0da9e7139950d26a0f4b0a766c2ff899e615a21b2749645b07bd7535e3a4dd065b052a671dc91c748fd29b8d2c04093525424ca43d7aaa4e88c34e77619c54cccf778894adf2b977d9fdc381520c689329b8872cd4f8607e4746d2729b0dbc8c073d3177322e215928519075d68859479d8f1c5376e9fce8bab3f4157bbafcc77a03fe449c0f6146702e0854b1207d249f1a3fb6456dd2059b06f23d5c1de937afab72edfb772f04d0360b5bd1444845f0cffd48908c37e0580ecf21c4985a448f6b816078d87a6715f43f9387dc902ea83ec26daba53fd836e230'
      );

      expect(binary).to.deep.equal(expectedBinary);
    });
  });

  describe('mnemonicToSeedBin', () => {
    it('should throw an error if the binary output length is not equal to SEED_SIZE', () => {
      const mnemonic = 'latch supply taxi india';

      expect(() => mnemonicToSeedBin(mnemonic)).to.throw('Unexpected MnemonicToSeedBin output size');
    });

    it('should generate seed binary of size SEED_SIZE from mnemonic', () => {
      const mnemonic =
        'reduce upon divert lean bird border smoke audio sydney form helm that amid robust famous crater saber nose shadow falcon sale flash blend candle pale crown injure creole govern brew flux mighty';
      const seedBinary = mnemonicToSeedBin(mnemonic);

      expect(seedBinary).to.have.length(COMMON.SEED_SIZE);
    });

    it('should generate seed binary from mnemonic', () => {
      const mnemonic =
        'decor help decade slate follow tenant june hare unruly malt order spat greed sodium mole sinful phrase tenor obey exist sugar cuff pest hybrid scute survey sail galaxy away eaten borrow aha';
      const seedBinary = mnemonicToSeedBin(mnemonic);
      const expectedSeedBinary = getUInt8ArrayFromHex(
        '38c689387cae54be0e75a652ee78609b8d1260ece58e9c90a2de149864a8da434ea246d7c14dbbbdb5a00f24401ac04a'
      );

      expect(seedBinary).to.deep.equal(expectedSeedBinary);
    });
  });

  describe('mnemonicToExtendedSeedBin', () => {
    it('should throw an error if the binary output length is not equal to SEED_SIZE', () => {
      const mnemonic = 'that amid robust famous';

      expect(() => mnemonicToExtendedSeedBin(mnemonic)).to.throw('Unexpected MnemonicToExtendedSeedBin output size');
    });

    it('should generate extended seed binary of size EXTENDED_SEED_SIZE from mnemonic', () => {
      const mnemonic =
        'soup jolt cook fill sonar orphan orbit taurus gene japan baby sydney cease heard clash alley birth theory caesar pile ledge karl packet cuff locate spill bout dour sample roar cinema leaf role river';
      const extendedSeedBinary = mnemonicToExtendedSeedBin(mnemonic);

      expect(extendedSeedBinary).to.have.length(COMMON.EXTENDED_SEED_SIZE);
    });

    it('should generate extended seed binary from mnemonic', () => {
      const mnemonic =
        'law unfair domino ballot got buck sandy why melt except amiss flee prove cried herd verge fully mosaic popery super opium loan wipe rough clout gate gather cloud import clause lovely slump seed splash';
      const extendedSeedBinary = mnemonicToExtendedSeedBin(mnemonic);
      const expectedSeedBinary = getUInt8ArrayFromHex(
        '7adedd3ea10d5f61ebbedf9a89d4a007e521ab9336690f2158e8fea88db29ae80afb1bb02c95b05b12c76eb2af82ecc6c22d28'
      );

      expect(extendedSeedBinary).to.deep.equal(expectedSeedBinary);
    });
  });
});

describe('Additional test cases for [helper]', () => {
  const extendedSeed = {
    '0105005ece2c787198e40d843e9696d0cf67373a0c7e110c475651928ae49e6764368ecce53914f8dbc62fa2571d3bf93aeff6':
      'absorb filled golf thesis koran body thrive streak dome heroic spain warsaw darken peak lewis ballet enter hardly mutual quest panama karl dale twice tier mucky which rust cool cat brew saxon depth zebra',
    '010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000':
      'absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback',
    '0104005969b326db865bb694a878e95b627e4a79d844891a2e0790d8011ea59ee47a119e1bc0a734593911d35515eeb2c46cc6':
      'absorb drank fusion orange chalky ripple gender hernia pope mole gave cheeky exile pack edit mummy coke laden strap barn plant unkind last bond bowl are crush native barley curlew bestow truly shady slump',
    '020600f429397626f9130f959cda184fa240b263a3699d481ce91141b718c733b53a8ba1a1f5a70972aa09cf5b0d100e27da5c':
      'action grape visa native kansas infant battle who owe pencil fifth cape recent demure heyday stamp break mrs due invade shrill desk deny roll peril game anyway clan appeal walker atlas abrupt cheek play',
    '0006007a0946f171a8b4ca0d44d8d78136286bb1d408923c99f8e58f5a4013852675a76930e00b82e9fc666e1dd30203a96b53':
      'aback grape laser needle velvet booze renal pear effect mist lofty grudge horror brick angle canopy omega modify moon pilot beard flew june keep cotton above lovely pastel havoc test spouse burial pour repent',
  };

  it('TestBinToMnemonic', () => {
    Object.getOwnPropertyNames(extendedSeed).forEach((eSeedStr) => {
      const eSeedArray = [];
      for (let c = 0; c < eSeedStr.length; c += 2) {
        eSeedArray.push(parseInt(eSeedStr.substring(c, c + 2), 16));
      }
      const eSeed = new Uint8Array(eSeedArray);
      const mnemonic = extendedSeedBinToMnemonic(eSeed);
      const expectedMnemonic = extendedSeed[eSeedStr];

      expect(mnemonic).to.equal(expectedMnemonic);
    });
  });

  it('TestMnemonicToBin', () => {
    Object.getOwnPropertyNames(extendedSeed).forEach((expectedESeed) => {
      const mnemonic = extendedSeed[expectedESeed];
      const eSeed = mnemonicToExtendedSeedBin(mnemonic);
      const eSeedStr = Array.from(eSeed, (byte) => byte.toString(16).padStart(2, '0')).join('');

      expect(expectedESeed).to.equal(eSeedStr);
    });
  });
});
