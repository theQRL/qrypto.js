import { sha256 as sha256$1 } from '@noble/hashes/sha256';
import jsSha3CommonJsPackage from 'js-sha3';
import { randomBytes } from '@noble/hashes/utils';

const CONSTANTS = Object.freeze({
  EXTENDED_PK_SIZE: 67,
  MAX_HEIGHT: 254,
});

const ENDIAN = Object.freeze({
  LITTLE: 0,
  BIG: 1,
});

const HASH_FUNCTION = Object.freeze({
  SHA2_256: 0,
  SHAKE_128: 1,
  SHAKE_256: 2,
});

const COMMON = Object.freeze({
  DESCRIPTOR_SIZE: 3,
  ADDRESS_SIZE: 20,
  SEED_SIZE: 48,
  EXTENDED_SEED_SIZE: 51,
  XMSS_SIG: 1,
  SHA256_2X: 0,
});

const WOTS_PARAM = Object.freeze({
  K: 2,
  W: 16,
  N: 32,
});

const OFFSET_IDX = 0;
const OFFSET_SK_SEED = OFFSET_IDX + 4;
const OFFSET_SK_PRF = OFFSET_SK_SEED + 32;
const OFFSET_PUB_SEED = OFFSET_SK_PRF + 32;
const OFFSET_ROOT = OFFSET_PUB_SEED + 32;

/// <reference path="typedefs.js" />


class TreeHashInstClass {
  constructor(n = 0) {
    [this.h] = new Uint32Array([0]);
    [this.nextIdx] = new Uint32Array([0]);
    [this.stackUsage] = new Uint32Array([0]);
    [this.completed] = new Uint8Array([0]);
    this.node = new Uint8Array(n);
  }
}

/**
 * @param {Uint32Array[number]} n
 * @returns {TreeHashInst}
 */
function newTreeHashInst(n) {
  return new TreeHashInstClass(n);
}

class BDSStateClass {
  constructor(height, n, k) {
    this.stackOffset = 0;
    this.stack = new Uint8Array((height + 1) * n);
    this.stackLevels = new Uint8Array(height + 1);
    this.auth = new Uint8Array(height * n);
    this.keep = new Uint8Array((height >>> 1) * n);
    this.treeHash = new Array(0);
    for (let i = 0; i < height - k; i++) {
      this.treeHash.push(newTreeHashInst(n));
    }
    this.retain = new Uint8Array(((1 << k) - k - 1) * n);
    this.nextLeaf = 0;
  }
}

/**
 * @param {Uint32Array[number]} height
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} k
 * @returns {BDSState}
 */
function newBDSState(height, n, k) {
  return new BDSStateClass(height, n, k);
}

class WOTSParamsClass {
  constructor(n, w) {
    this.n = n;
    this.w = w;
    [this.logW] = new Uint32Array([Math.log2(w)]);
    if (this.logW !== 2 && this.logW !== 4 && this.logW !== 8) {
      throw new Error('logW should be either 2, 4 or 8');
    }
    // an integer value is passed to the ceil function for now w.r.t. golang code. update this as and when required.
    [this.len1] = new Uint32Array([Math.ceil(parseInt(((8 * n) / this.logW).toString(), 10))]);
    [this.len2] = new Uint32Array([Math.floor(Math.log2(this.len1 * (w - 1)) / this.logW) + 1]);
    this.len = this.len1 + this.len2;
    this.keySize = this.len * n;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} w
 * @returns {WOTSParams}
 */
function newWOTSParams(n, w) {
  return new WOTSParamsClass(n, w);
}

class XMSSParamsClass {
  constructor(n, h, w, k) {
    this.wotsParams = newWOTSParams(n, w);
    this.n = n;
    this.h = h;
    this.k = k;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint32Array[number]} w
 * @param {Uint32Array[number]} k
 * @returns {XMSSParams}
 */
function newXMSSParams(n, h, w, k) {
  return new XMSSParamsClass(n, h, w, k);
}

class QRLDescriptorClass {
  /** @returns {Uint8Array[number]} */
  getHeight() {
    return this.height;
  }

  /** @returns {HashFunction} */
  getHashFunction() {
    return this.hashFunction;
  }

  /** @returns {SignatureType} */
  getSignatureType() {
    return this.signatureType;
  }

  /** @returns {AddrFormatType} */
  getAddrFormatType() {
    return this.addrFormatType;
  }

  /** @returns {Uint8Array} */
  getBytes() {
    const output = new Uint8Array(COMMON.DESCRIPTOR_SIZE);
    output.set([(this.signatureType << 4) | (this.hashFunction & 0x0f)], 0);
    output.set([(this.addrFormatType << 4) | ((this.height >>> 1) & 0x0f)], 1);
    return output;
  }

  constructor(hashFunction, signatureType, height, addrFormatType) {
    this.hashFunction = hashFunction;
    this.signatureType = signatureType;
    this.height = height;
    this.addrFormatType = addrFormatType;
  }
}

/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {SignatureType} signatureType
 * @param {AddrFormatType} addrFormatType
 * @returns {QRLDescriptor}
 */
function newQRLDescriptor(height, hashFunction, signatureType, addrFormatType) {
  return new QRLDescriptorClass(hashFunction, signatureType, height, addrFormatType);
}

/**
 * @param {Uint8Array} descriptorBytes
 * @returns {QRLDescriptor}
 */
function newQRLDescriptorFromBytes(descriptorBytes) {
  if (descriptorBytes.length !== 3) {
    throw new Error('Descriptor size should be 3 bytes');
  }

  return new QRLDescriptorClass(
    descriptorBytes[0] & 0x0f,
    (descriptorBytes[0] >>> 4) & 0x0f,
    (descriptorBytes[1] & 0x0f) << 1,
    (descriptorBytes[1] & 0xf0) >>> 4
  );
}

/**
 * @param {Uint8Array} extendedSeed
 * @returns {QRLDescriptor}
 */
function newQRLDescriptorFromExtendedSeed(extendedSeed) {
  if (extendedSeed.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  return newQRLDescriptorFromBytes(extendedSeed.subarray(0, COMMON.DESCRIPTOR_SIZE));
}

/**
 * @param {Uint8Array} extendedPk
 * @returns {QRLDescriptor}
 */
function newQRLDescriptorFromExtendedPk(extendedPk) {
  if (extendedPk.length !== CONSTANTS.EXTENDED_PK_SIZE) {
    throw new Error(`extendedPk should be an array of size ${CONSTANTS.EXTENDED_PK_SIZE}`);
  }

  return newQRLDescriptorFromBytes(extendedPk.subarray(0, COMMON.DESCRIPTOR_SIZE));
}

var WORD_LIST = [
  'aback',
  'abbey',
  'abbot',
  'abide',
  'ablaze',
  'able',
  'aboard',
  'abode',
  'abort',
  'abound',
  'about',
  'above',
  'abra',
  'abroad',
  'abrupt',
  'absent',
  'absorb',
  'absurd',
  'accent',
  'accept',
  'access',
  'accord',
  'accuse',
  'ace',
  'ache',
  'aching',
  'acid',
  'acidic',
  'acorn',
  'acre',
  'across',
  'act',
  'action',
  'active',
  'actor',
  'actual',
  'acute',
  'adam',
  'adapt',
  'add',
  'added',
  'adept',
  'adhere',
  'adjust',
  'admire',
  'admit',
  'adobe',
  'adopt',
  'adrift',
  'adverb',
  'advert',
  'aedes',
  'aerial',
  'afar',
  'affair',
  'affect',
  'afford',
  'afghan',
  'afield',
  'afloat',
  'afraid',
  'afresh',
  'after',
  'again',
  'age',
  'agency',
  'agenda',
  'agent',
  'aghast',
  'agile',
  'ago',
  'agony',
  'agree',
  'agreed',
  'aha',
  'ahead',
  'aid',
  'aide',
  'aim',
  'air',
  'airman',
  'airy',
  'akin',
  'alarm',
  'alaska',
  'albeit',
  'album',
  'alert',
  'alibi',
  'alice',
  'alien',
  'alight',
  'align',
  'alike',
  'alive',
  'alkali',
  'all',
  'allars',
  'allay',
  'alley',
  'allied',
  'allot',
  'allow',
  'alloy',
  'ally',
  'almond',
  'almost',
  'aloft',
  'alone',
  'along',
  'aloof',
  'aloud',
  'alpha',
  'alpine',
  'also',
  'altar',
  'alter',
  'always',
  'amaze',
  'amazon',
  'amber',
  'ambush',
  'amen',
  'amend',
  'amid',
  'amidst',
  'amiss',
  'among',
  'amount',
  'ample',
  'amuse',
  'anchor',
  'and',
  'andrew',
  'anew',
  'angel',
  'anger',
  'angle',
  'anglo',
  'angola',
  'animal',
  'ankle',
  'annoy',
  'annual',
  'answer',
  'anthem',
  'anti',
  'antony',
  'anubis',
  'any',
  'anyhow',
  'anyway',
  'apart',
  'apathy',
  'apex',
  'apiece',
  'appeal',
  'appear',
  'apple',
  'apply',
  'april',
  'apron',
  'arcade',
  'arcane',
  'arch',
  'arctic',
  'ardent',
  'are',
  'area',
  'argue',
  'arid',
  'arise',
  'arm',
  'armful',
  'armpit',
  'army',
  'aroma',
  'around',
  'arouse',
  'array',
  'arrest',
  'arrive',
  'arrow',
  'arson',
  'art',
  'artery',
  'artful',
  'artist',
  'ascent',
  'ashen',
  'ashore',
  'aside',
  'ask',
  'asleep',
  'aspect',
  'assay',
  'assent',
  'assert',
  'assess',
  'asset',
  'assign',
  'assist',
  'assume',
  'assure',
  'asthma',
  'astute',
  'asylum',
  'ate',
  'athens',
  'atlas',
  'atom',
  'atomic',
  'atop',
  'attach',
  'attain',
  'attend',
  'attic',
  'auburn',
  'audio',
  'audit',
  'augite',
  'august',
  'aunt',
  'auntie',
  'aura',
  'austin',
  'auteur',
  'author',
  'auto',
  'autumn',
  'avail',
  'avenge',
  'avenue',
  'avert',
  'avid',
  'avoid',
  'await',
  'awake',
  'awaken',
  'award',
  'aware',
  'awash',
  'away',
  'awful',
  'awhile',
  'axes',
  'axiom',
  'axis',
  'axle',
  'aye',
  'baby',
  'bach',
  'back',
  'backup',
  'bacon',
  'bad',
  'badge',
  'badly',
  'bag',
  'baggy',
  'bail',
  'bait',
  'bake',
  'baker',
  'bakery',
  'bald',
  'ball',
  'ballad',
  'ballet',
  'ballot',
  'baltic',
  'bamboo',
  'ban',
  'banal',
  'banana',
  'band',
  'banjo',
  'bank',
  'bar',
  'barber',
  'bare',
  'barely',
  'barge',
  'baric',
  'bark',
  'barley',
  'barn',
  'baron',
  'barrel',
  'barren',
  'basalt',
  'base',
  'basic',
  'basil',
  'basin',
  'basis',
  'basket',
  'basque',
  'bass',
  'bat',
  'batch',
  'bath',
  'bathe',
  'baton',
  'battle',
  'bay',
  'beach',
  'beacon',
  'beak',
  'beam',
  'bean',
  'bear',
  'beard',
  'beat',
  'beauty',
  'become',
  'bed',
  'beech',
  'beef',
  'beefy',
  'beep',
  'beer',
  'beet',
  'beetle',
  'before',
  'beggar',
  'begin',
  'behalf',
  'behave',
  'behind',
  'beige',
  'being',
  'belfry',
  'belief',
  'bell',
  'belly',
  'belong',
  'below',
  'belt',
  'bench',
  'bend',
  'bended',
  'benign',
  'bent',
  'berlin',
  'berry',
  'berth',
  'beset',
  'beside',
  'best',
  'bestow',
  'bet',
  'beta',
  'betray',
  'better',
  'betty',
  'beware',
  'beyond',
  'bias',
  'biceps',
  'bicker',
  'bid',
  'big',
  'bike',
  'bile',
  'bill',
  'binary',
  'bind',
  'biopsy',
  'birch',
  'bird',
  'birdie',
  'birth',
  'bishop',
  'bit',
  'bite',
  'bitter',
  'blade',
  'blame',
  'bland',
  'blaser',
  'blast',
  'blaze',
  'bleak',
  'blend',
  'bless',
  'blew',
  'blink',
  'blip',
  'bliss',
  'blitz',
  'block',
  'blond',
  'blood',
  'bloom',
  'blot',
  'blouse',
  'blue',
  'bluff',
  'blunt',
  'blur',
  'blush',
  'boar',
  'board',
  'boast',
  'boat',
  'bocage',
  'bodily',
  'body',
  'bogus',
  'boil',
  'bold',
  'bolt',
  'bombay',
  'bond',
  'bone',
  'bonn',
  'bonnet',
  'bonus',
  'bony',
  'book',
  'boost',
  'boot',
  'booth',
  'booze',
  'bop',
  'border',
  'bore',
  'borrow',
  'bosom',
  'boss',
  'boston',
  'both',
  'bother',
  'bottle',
  'bottom',
  'bought',
  'bounce',
  'bound',
  'bounty',
  'bout',
  'bovine',
  'bow',
  'bowel',
  'bowl',
  'box',
  'boy',
  'boyish',
  'brace',
  'brain',
  'brainy',
  'brake',
  'bran',
  'branch',
  'brand',
  'brandy',
  'brass',
  'brave',
  'bravo',
  'brazil',
  'breach',
  'bread',
  'break',
  'breath',
  'bred',
  'breed',
  'breeze',
  'brew',
  'brick',
  'bride',
  'bridge',
  'brief',
  'bright',
  'brim',
  'brine',
  'bring',
  'brink',
  'brisk',
  'briton',
  'broad',
  'broke',
  'broken',
  'bronze',
  'brook',
  'broom',
  'brown',
  'bruise',
  'brush',
  'brutal',
  'brute',
  'bubble',
  'buck',
  'bucket',
  'buckle',
  'buddha',
  'budget',
  'buen',
  'buffet',
  'buggy',
  'build',
  'bulb',
  'bulge',
  'bulk',
  'bulky',
  'bull',
  'bullet',
  'bully',
  'bump',
  'bumpy',
  'bunch',
  'bundle',
  'bunk',
  'bunny',
  'burden',
  'bureau',
  'burial',
  'burly',
  'burma',
  'burned',
  'burnt',
  'burrow',
  'burst',
  'bury',
  'bus',
  'bush',
  'bust',
  'bustle',
  'busy',
  'but',
  'butler',
  'butter',
  'button',
  'buy',
  'buyer',
  'buzz',
  'bye',
  'byte',
  'byways',
  'cab',
  'cabin',
  'cable',
  'cache',
  'cactus',
  'caesar',
  'cage',
  'cagey',
  'cahot',
  'cain',
  'cairo',
  'cake',
  'cakile',
  'calf',
  'call',
  'caller',
  'calm',
  'calmly',
  'came',
  'camel',
  'camera',
  'camp',
  'campus',
  'can',
  'canada',
  'canary',
  'cancel',
  'candid',
  'candle',
  'candy',
  'cane',
  'canine',
  'canna',
  'canoe',
  'canopy',
  'canvas',
  'canyon',
  'cap',
  'cape',
  'car',
  'carbon',
  'card',
  'care',
  'career',
  'caress',
  'cargo',
  'carl',
  'carnal',
  'carol',
  'carp',
  'carpet',
  'carrot',
  'carry',
  'cart',
  'cartel',
  'case',
  'cash',
  'cask',
  'cast',
  'castle',
  'casual',
  'cat',
  'catch',
  'cater',
  'cattle',
  'caught',
  'causal',
  'cause',
  'cave',
  'cease',
  'celery',
  'cell',
  'cellar',
  'celtic',
  'cement',
  'censor',
  'census',
  'cereal',
  'cervix',
  'chain',
  'chair',
  'chalet',
  'chalk',
  'chalky',
  'champ',
  'chance',
  'change',
  'chant',
  'chaos',
  'chap',
  'chapel',
  'charge',
  'charm',
  'chart',
  'chase',
  'chat',
  'cheap',
  'cheat',
  'check',
  'cheek',
  'cheeky',
  'cheer',
  'cheery',
  'cheese',
  'chef',
  'cherry',
  'chess',
  'chest',
  'chew',
  'chic',
  'chick',
  'chief',
  'child',
  'chile',
  'chill',
  'chilly',
  'china',
  'chip',
  'choice',
  'choir',
  'choose',
  'chop',
  'choppy',
  'chord',
  'chorus',
  'chose',
  'chosen',
  'choux',
  'chrome',
  'chunk',
  'chunky',
  'cider',
  'cigar',
  'cinema',
  'circa',
  'circle',
  'circus',
  'cite',
  'city',
  'civic',
  'civil',
  'clad',
  'claim',
  'clammy',
  'clan',
  'clap',
  'clash',
  'clasp',
  'class',
  'clause',
  'claw',
  'clay',
  'clean',
  'clear',
  'clergy',
  'clerk',
  'clever',
  'click',
  'client',
  'cliff',
  'climax',
  'climb',
  'clinch',
  'cling',
  'clinic',
  'clip',
  'cloak',
  'clock',
  'clone',
  'close',
  'closer',
  'closet',
  'cloth',
  'cloud',
  'cloudy',
  'clout',
  'clown',
  'club',
  'clue',
  'clumsy',
  'clung',
  'clutch',
  'coach',
  'coal',
  'coast',
  'coat',
  'coax',
  'cobalt',
  'cobble',
  'cobra',
  'coca',
  'cocoa',
  'code',
  'coffee',
  'coffin',
  'cohort',
  'coil',
  'coin',
  'coke',
  'cold',
  'collar',
  'colon',
  'colony',
  'colt',
  'column',
  'comb',
  'combat',
  'come',
  'comedy',
  'comes',
  'comic',
  'commit',
  'common',
  'compel',
  'comply',
  'concur',
  'cone',
  'confer',
  'congo',
  'consul',
  'convex',
  'convey',
  'convoy',
  'cook',
  'cool',
  'cope',
  'copper',
  'copy',
  'coral',
  'cord',
  'core',
  'cork',
  'corn',
  'corner',
  'corps',
  'corpse',
  'corpus',
  'cortex',
  'cosmic',
  'cosmos',
  'cost',
  'costia',
  'costly',
  'cosy',
  'cotton',
  'couch',
  'cough',
  'could',
  'count',
  'county',
  'coup',
  'couple',
  'coupon',
  'course',
  'court',
  'cousin',
  'cove',
  'cover',
  'covert',
  'cow',
  'coward',
  'cowboy',
  'crab',
  'cradle',
  'craft',
  'crafty',
  'crag',
  'crane',
  'crate',
  'crater',
  'crawl',
  'crazy',
  'creak',
  'cream',
  'create',
  'credit',
  'creed',
  'creek',
  'creep',
  'creepy',
  'creole',
  'crept',
  'crest',
  'crew',
  'cried',
  'crisis',
  'crisp',
  'critic',
  'croft',
  'crook',
  'crop',
  'cross',
  'crow',
  'crowd',
  'crown',
  'crude',
  'cruel',
  'cruise',
  'crunch',
  'crush',
  'crust',
  'crux',
  'cry',
  'crypt',
  'cuba',
  'cube',
  'cubic',
  'cuckoo',
  'cuff',
  'cult',
  'cup',
  'curb',
  'cure',
  'curfew',
  'curl',
  'curlew',
  'curry',
  'curse',
  'cursor',
  'curve',
  'custom',
  'cut',
  'cute',
  'cycle',
  'cyclic',
  'cynic',
  'cyprus',
  'czech',
  'dad',
  'daddy',
  'dagger',
  'daily',
  'dairy',
  'daisy',
  'dale',
  'dallas',
  'damage',
  'damp',
  'dampen',
  'dance',
  'danger',
  'daniel',
  'danish',
  'dare',
  'dark',
  'darken',
  'darwin',
  'dash',
  'data',
  'date',
  'david',
  'dawn',
  'day',
  'deadly',
  'deaf',
  'deal',
  'dealer',
  'dean',
  'dear',
  'debar',
  'debate',
  'debit',
  'debris',
  'debt',
  'debtor',
  'decade',
  'decay',
  'decent',
  'decide',
  'deck',
  'decor',
  'decree',
  'deduce',
  'deed',
  'deep',
  'deeply',
  'deer',
  'defeat',
  'defect',
  'defend',
  'defer',
  'define',
  'defy',
  'degree',
  'deity',
  'delay',
  'delete',
  'delhi',
  'delphi',
  'delta',
  'demand',
  'demise',
  'demo',
  'demure',
  'denial',
  'denote',
  'dense',
  'dental',
  'deny',
  'depart',
  'depend',
  'depict',
  'deploy',
  'depot',
  'depth',
  'deputy',
  'derby',
  'derive',
  'desert',
  'design',
  'desist',
  'desk',
  'detail',
  'detect',
  'deter',
  'detest',
  'detour',
  'device',
  'devise',
  'devoid',
  'devote',
  'devour',
  'dial',
  'diana',
  'diary',
  'dice',
  'dictum',
  'did',
  'diesel',
  'diet',
  'differ',
  'digest',
  'digit',
  'dine',
  'dinghy',
  'dingus',
  'dinner',
  'diode',
  'dire',
  'direct',
  'dirt',
  'disc',
  'disco',
  'dish',
  'disk',
  'dismal',
  'dispel',
  'ditch',
  'divert',
  'divide',
  'divine',
  'dizzy',
  'docile',
  'dock',
  'doctor',
  'dog',
  'dogger',
  'dogma',
  'dole',
  'doll',
  'dollar',
  'dolly',
  'domain',
  'dome',
  'domino',
  'donate',
  'done',
  'donkey',
  'donor',
  'door',
  'dorsal',
  'dose',
  'dote',
  'double',
  'doubt',
  'dough',
  'dour',
  'dove',
  'dower',
  'down',
  'dozen',
  'draft',
  'drag',
  'dragon',
  'drain',
  'drama',
  'drank',
  'draper',
  'draw',
  'drawer',
  'dread',
  'dream',
  'dreamy',
  'dreary',
  'dress',
  'drew',
  'dried',
  'drift',
  'drill',
  'drink',
  'drip',
  'drive',
  'driver',
  'drool',
  'drop',
  'drove',
  'drown',
  'drum',
  'dry',
  'dual',
  'dublin',
  'duck',
  'duct',
  'due',
  'duel',
  'duet',
  'duke',
  'dull',
  'duly',
  'dummy',
  'dump',
  'dune',
  'dung',
  'duress',
  'during',
  'dusk',
  'dust',
  'dusty',
  'dutch',
  'duty',
  'dwarf',
  'dwell',
  'dyer',
  'dying',
  'dynamo',
  'each',
  'eager',
  'eagle',
  'ear',
  'earl',
  'early',
  'earn',
  'earth',
  'ease',
  'easel',
  'easily',
  'east',
  'easter',
  'easy',
  'eat',
  'eaten',
  'eater',
  'echo',
  'eddy',
  'eden',
  'edge',
  'edible',
  'edict',
  'edit',
  'editor',
  'edward',
  'eerie',
  'eerily',
  'effect',
  'effort',
  'egg',
  'ego',
  'egypt',
  'eight',
  'eighth',
  'eighty',
  'either',
  'elbow',
  'elder',
  'eldest',
  'elect',
  'eleven',
  'elicit',
  'elite',
  'eloge',
  'else',
  'elude',
  'elves',
  'embark',
  'emblem',
  'embryo',
  'emerge',
  'emit',
  'empire',
  'employ',
  'empty',
  'enable',
  'enamel',
  'end',
  'endure',
  'energy',
  'engage',
  'engine',
  'enjoy',
  'enlist',
  'enough',
  'ensure',
  'entail',
  'enter',
  'entire',
  'entre',
  'entry',
  'envoy',
  'envy',
  'enzyme',
  'epic',
  'epoch',
  'equal',
  'equate',
  'equip',
  'equity',
  'era',
  'erase',
  'eric',
  'erode',
  'erotic',
  'errant',
  'error',
  'escape',
  'essay',
  'essex',
  'estate',
  'esteem',
  'ethic',
  'etoile',
  'eundo',
  'europe',
  'evade',
  'eve',
  'even',
  'event',
  'ever',
  'every',
  'evict',
  'evil',
  'evoke',
  'evolve',
  'exact',
  'exam',
  'exceed',
  'excel',
  'except',
  'excess',
  'excise',
  'excite',
  'excuse',
  'exempt',
  'exert',
  'exile',
  'exist',
  'exit',
  'exodus',
  'exotic',
  'expand',
  'expect',
  'expert',
  'expire',
  'export',
  'expose',
  'extend',
  'extra',
  'exulat',
  'eye',
  'eyed',
  'fabric',
  'face',
  'facer',
  'facial',
  'fact',
  'factor',
  'fade',
  'fail',
  'faint',
  'fair',
  'fairly',
  'fake',
  'falcon',
  'fall',
  'false',
  'falter',
  'fame',
  'family',
  'famine',
  'famous',
  'fan',
  'fancy',
  'far',
  'farce',
  'fare',
  'farm',
  'farmer',
  'fast',
  'fasten',
  'faster',
  'fatal',
  'fate',
  'father',
  'fatty',
  'fault',
  'faulty',
  'fauna',
  'feast',
  'feat',
  'fed',
  'fee',
  'feeble',
  'feed',
  'feel',
  'feels',
  'feet',
  'fell',
  'fellow',
  'felt',
  'female',
  'femur',
  'fence',
  'fend',
  'ferry',
  'fetal',
  'fetch',
  'feudal',
  'fever',
  'few',
  'fewer',
  'fiance',
  'fiasco',
  'fiddle',
  'field',
  'fiend',
  'fierce',
  'fiery',
  'fifth',
  'fifty',
  'fig',
  'figure',
  'file',
  'fill',
  'filled',
  'filler',
  'film',
  'filter',
  'filth',
  'filthy',
  'final',
  'finale',
  'find',
  'fine',
  'finish',
  'finite',
  'firm',
  'firmly',
  'first',
  'fiscal',
  'fish',
  'fisher',
  'fit',
  'fitful',
  'five',
  'fix',
  'flag',
  'flair',
  'flak',
  'flame',
  'flank',
  'flare',
  'flash',
  'flask',
  'flat',
  'flaw',
  'fled',
  'flee',
  'fleece',
  'fleet',
  'flesh',
  'fleshy',
  'flew',
  'flick',
  'flight',
  'flimsy',
  'flint',
  'flirt',
  'float',
  'flock',
  'floe',
  'flood',
  'floor',
  'floppy',
  'flora',
  'floral',
  'flour',
  'flow',
  'flower',
  'fluent',
  'fluffy',
  'fluid',
  'flung',
  'flurry',
  'flush',
  'flute',
  'flux',
  'fly',
  'flyer',
  'foal',
  'foam',
  'foamy',
  'focal',
  'focus',
  'fog',
  'foil',
  'foin',
  'fold',
  'folk',
  'follow',
  'folly',
  'fond',
  'fondly',
  'font',
  'food',
  'fool',
  'foot',
  'for',
  'forbid',
  'force',
  'ford',
  'forest',
  'forge',
  'forget',
  'fork',
  'form',
  'formal',
  'format',
  'former',
  'fort',
  'forth',
  'forty',
  'forum',
  'fossil',
  'foster',
  'foul',
  'found',
  'four',
  'fourth',
  'fox',
  'foyer',
  'frail',
  'frame',
  'franc',
  'france',
  'frank',
  'free',
  'freed',
  'freely',
  'freer',
  'freeze',
  'french',
  'frenzy',
  'fresh',
  'friar',
  'friday',
  'fridge',
  'fried',
  'friend',
  'fright',
  'fringe',
  'frock',
  'frog',
  'from',
  'front',
  'frost',
  'frosty',
  'frown',
  'frozen',
  'frugal',
  'fruit',
  'fruity',
  'fudge',
  'fuel',
  'fulfil',
  'full',
  'fully',
  'fun',
  'fund',
  'funny',
  'fur',
  'furry',
  'fury',
  'fuse',
  'fusion',
  'fuss',
  'fussy',
  'futile',
  'future',
  'fuzzy',
  'gadget',
  'gag',
  'gain',
  'gala',
  'galaxy',
  'gale',
  'gall',
  'galley',
  'gallon',
  'gallop',
  'gamble',
  'game',
  'gamma',
  'gandhi',
  'gap',
  'garage',
  'garden',
  'garlic',
  'gas',
  'gasp',
  'gate',
  'gather',
  'gaucho',
  'gauge',
  'gaul',
  'gaunt',
  'gave',
  'gaze',
  'gear',
  'geese',
  'gemini',
  'gender',
  'gene',
  'geneva',
  'genial',
  'genius',
  'genre',
  'gentle',
  'gently',
  'gentry',
  'genus',
  'george',
  'get',
  'ghetto',
  'ghost',
  'giant',
  'gift',
  'giggle',
  'gill',
  'gilt',
  'ginger',
  'girl',
  'give',
  'given',
  'glad',
  'glade',
  'glance',
  'gland',
  'glare',
  'glass',
  'glassy',
  'gleam',
  'glee',
  'glib',
  'glide',
  'global',
  'globe',
  'gloom',
  'gloomy',
  'gloria',
  'glory',
  'gloss',
  'glossy',
  'glove',
  'glow',
  'glue',
  'goal',
  'goat',
  'gold',
  'golden',
  'golf',
  'gone',
  'gong',
  'good',
  'goose',
  'gorge',
  'gory',
  'gosh',
  'gospel',
  'gossip',
  'got',
  'gothic',
  'govern',
  'gown',
  'grab',
  'grace',
  'grade',
  'grain',
  'grand',
  'grant',
  'grape',
  'graph',
  'grasp',
  'grass',
  'grassy',
  'grate',
  'grave',
  'gravel',
  'gravy',
  'gray',
  'grease',
  'greasy',
  'great',
  'greece',
  'greed',
  'greedy',
  'greek',
  'green',
  'greet',
  'grew',
  'grey',
  'grid',
  'grief',
  'grill',
  'grim',
  'grin',
  'grind',
  'grip',
  'grit',
  'gritty',
  'groan',
  'groin',
  'groom',
  'groove',
  'ground',
  'group',
  'grove',
  'grow',
  'grown',
  'growth',
  'grudge',
  'grunt',
  'guard',
  'guess',
  'guest',
  'guide',
  'guild',
  'guilt',
  'guilty',
  'guise',
  'guitar',
  'gulf',
  'gully',
  'gunman',
  'guru',
  'gut',
  'guy',
  'gypsy',
  'habit',
  'hack',
  'had',
  'hague',
  'hail',
  'hair',
  'hairy',
  'haiti',
  'hale',
  'half',
  'hall',
  'halt',
  'hamlet',
  'hammer',
  'hand',
  'handle',
  'handy',
  'hang',
  'hangar',
  'hanoi',
  'happen',
  'happy',
  'hard',
  'hardly',
  'hare',
  'harm',
  'harp',
  'harry',
  'harsh',
  'has',
  'hash',
  'hassle',
  'hasta',
  'haste',
  'hasten',
  'hasty',
  'hat',
  'hatch',
  'hate',
  'haul',
  'haunt',
  'havana',
  'have',
  'haven',
  'havoc',
  'hawaii',
  'hawk',
  'hawse',
  'hazard',
  'haze',
  'hazel',
  'hazy',
  'heal',
  'health',
  'heap',
  'hear',
  'heard',
  'heart',
  'hearth',
  'hearty',
  'heat',
  'heater',
  'heaven',
  'heavy',
  'hebrew',
  'heck',
  'hectic',
  'hedge',
  'heel',
  'hefty',
  'height',
  'heil',
  'heir',
  'held',
  'helium',
  'helix',
  'hello',
  'helm',
  'helmet',
  'help',
  'hemp',
  'hence',
  'henry',
  'her',
  'herald',
  'herb',
  'herd',
  'here',
  'hereby',
  'hermes',
  'hernia',
  'hero',
  'heroic',
  'hest',
  'hey',
  'heyday',
  'hick',
  'hidden',
  'hide',
  'high',
  'higher',
  'highly',
  'hill',
  'him',
  'hind',
  'hindu',
  'hint',
  'hippy',
  'hire',
  'his',
  'hiss',
  'hit',
  'hive',
  'hoard',
  'hoarse',
  'hobby',
  'hockey',
  'hold',
  'holder',
  'hollow',
  'holly',
  'holy',
  'home',
  'honest',
  'honey',
  'hood',
  'hope',
  'hopple',
  'horrid',
  'horror',
  'horse',
  'hose',
  'host',
  'hotbox',
  'hotel',
  'hound',
  'hour',
  'house',
  'hover',
  'how',
  'huck',
  'huge',
  'hull',
  'human',
  'humane',
  'humble',
  'humid',
  'hung',
  'hunger',
  'hungry',
  'hunt',
  'hurdle',
  'hurl',
  'hurry',
  'hurt',
  'hush',
  'hut',
  'hybrid',
  'hymn',
  'hyphen',
  'ice',
  'icing',
  'icon',
  'idaho',
  'idea',
  'ideal',
  'idiom',
  'idle',
  'idly',
  'idol',
  'ignite',
  'ignore',
  'ill',
  'image',
  'immune',
  'impact',
  'imply',
  'import',
  'impose',
  'inca',
  'inch',
  'income',
  'incur',
  'indeed',
  'index',
  'india',
  'indian',
  'indoor',
  'induce',
  'inept',
  'inert',
  'infant',
  'infect',
  'infer',
  'influx',
  'inform',
  'inhere',
  'inject',
  'injure',
  'injury',
  'ink',
  'inlaid',
  'inland',
  'inlet',
  'inmate',
  'inn',
  'innate',
  'inner',
  'input',
  'insane',
  'insect',
  'insert',
  'inset',
  'inside',
  'insist',
  'insult',
  'insure',
  'intact',
  'intake',
  'intend',
  'inter',
  'into',
  'invade',
  'invent',
  'invest',
  'invite',
  'invoke',
  'inward',
  'iowa',
  'iran',
  'iraq',
  'irish',
  'iron',
  'ironic',
  'irony',
  'isaac',
  'isabel',
  'islam',
  'island',
  'isle',
  'issue',
  'italy',
  'item',
  'itself',
  'ivan',
  'ivory',
  'ivy',
  'jacket',
  'jacob',
  'jaguar',
  'jail',
  'james',
  'japan',
  'jargon',
  'java',
  'jaw',
  'jazz',
  'jeep',
  'jelly',
  'jerky',
  'jersey',
  'jest',
  'jet',
  'jewel',
  'jim',
  'jive',
  'job',
  'jock',
  'jockey',
  'john',
  'join',
  'joke',
  'jolly',
  'jolt',
  'jordan',
  'joseph',
  'joy',
  'joyful',
  'joyous',
  'judas',
  'judge',
  'judy',
  'juice',
  'juicy',
  'july',
  'jumble',
  'jumbo',
  'jump',
  'june',
  'jungle',
  'junior',
  'junk',
  'junta',
  'jury',
  'just',
  'kami',
  'kansas',
  'karate',
  'karl',
  'karma',
  'kedge',
  'keel',
  'keen',
  'keep',
  'keeper',
  'kenya',
  'kept',
  'kernel',
  'kettle',
  'key',
  'khaki',
  'khaya',
  'khowar',
  'kick',
  'kidnap',
  'kidney',
  'kin',
  'kind',
  'kindly',
  'king',
  'kiss',
  'kite',
  'kitten',
  'knack',
  'knaggy',
  'knee',
  'knew',
  'knight',
  'knit',
  'knock',
  'knot',
  'know',
  'known',
  'koran',
  'korea',
  'kusan',
  'kuwait',
  'label',
  'lace',
  'lack',
  'lad',
  'ladder',
  'laden',
  'lady',
  'lagoon',
  'laity',
  'lake',
  'lamb',
  'lame',
  'lamp',
  'lance',
  'land',
  'lane',
  'laos',
  'lap',
  'lapse',
  'large',
  'larval',
  'laser',
  'last',
  'latch',
  'late',
  'lately',
  'latent',
  'later',
  'latest',
  'latter',
  'laugh',
  'launch',
  'lava',
  'lavish',
  'law',
  'lawful',
  'lawn',
  'laws',
  'lawyer',
  'lay',
  'layer',
  'layman',
  'lazy',
  'lead',
  'leader',
  'leaf',
  'leafy',
  'league',
  'leak',
  'leaky',
  'lean',
  'leap',
  'learn',
  'lease',
  'leash',
  'least',
  'leave',
  'led',
  'ledge',
  'left',
  'leg',
  'legacy',
  'legal',
  'legend',
  'legion',
  'lemon',
  'lend',
  'length',
  'lens',
  'lent',
  'leo',
  'leper',
  'lese',
  'lesion',
  'less',
  'lessen',
  'lesser',
  'lesson',
  'lest',
  'let',
  'lethal',
  'letter',
  'letup',
  'level',
  'lever',
  'levy',
  'lewis',
  'liable',
  'liar',
  'libel',
  'libya',
  'lice',
  'lick',
  'lid',
  'lie',
  'lied',
  'life',
  'lift',
  'light',
  'like',
  'likely',
  'lima',
  'limb',
  'lime',
  'limit',
  'limp',
  'line',
  'linear',
  'linen',
  'lineup',
  'linger',
  'link',
  'lion',
  'lip',
  'liquid',
  'lisbon',
  'list',
  'listen',
  'lit',
  'live',
  'lively',
  'liver',
  'livy',
  'liz',
  'lizard',
  'load',
  'loaf',
  'loan',
  'lobby',
  'lobe',
  'local',
  'locate',
  'lock',
  'locus',
  'lodge',
  'loft',
  'lofty',
  'log',
  'logic',
  'logo',
  'london',
  'lone',
  'lonely',
  'long',
  'longer',
  'look',
  'loop',
  'loose',
  'loosen',
  'loot',
  'lord',
  'lorry',
  'lose',
  'loss',
  'lost',
  'lot',
  'lotus',
  'loud',
  'loudly',
  'lounge',
  'lousy',
  'louvre',
  'love',
  'lovely',
  'lover',
  'low',
  'lower',
  'lowest',
  'loyal',
  'lucid',
  'luck',
  'lucky',
  'lucy',
  'lukes',
  'lull',
  'lump',
  'lumpy',
  'lunacy',
  'lunar',
  'lunch',
  'lung',
  'lure',
  'lurid',
  'lush',
  'lusory',
  'lute',
  'luther',
  'luxury',
  'lying',
  'lymph',
  'lyric',
  'macho',
  'macro',
  'macte',
  'madam',
  'madame',
  'made',
  'madrid',
  'magic',
  'magma',
  'magnet',
  'magnum',
  'maid',
  'maiden',
  'mail',
  'main',
  'mainly',
  'major',
  'make',
  'maker',
  'male',
  'malice',
  'mall',
  'malt',
  'malta',
  'mammal',
  'manage',
  'mane',
  'mania',
  'manic',
  'manila',
  'manner',
  'manor',
  'mantle',
  'manual',
  'manure',
  'many',
  'map',
  'maple',
  'marble',
  'march',
  'mare',
  'margin',
  'maria',
  'marina',
  'mark',
  'market',
  'marry',
  'mars',
  'marsh',
  'martin',
  'martyr',
  'mary',
  'mask',
  'mason',
  'mass',
  'mast',
  'match',
  'mate',
  'matrix',
  'matter',
  'mature',
  'maxim',
  'may',
  'maya',
  'maybe',
  'mayor',
  'maze',
  'mead',
  'meadow',
  'meal',
  'mean',
  'meant',
  'meat',
  'mecca',
  'medal',
  'media',
  'median',
  'medic',
  'medium',
  'meet',
  'mellow',
  'melody',
  'melon',
  'melt',
  'member',
  'memo',
  'memory',
  'menace',
  'mend',
  'mental',
  'mentor',
  'menu',
  'mercy',
  'mere',
  'merely',
  'merge',
  'merger',
  'merit',
  'merry',
  'mesh',
  'mess',
  'messy',
  'met',
  'metal',
  'meter',
  'method',
  'methyl',
  'metric',
  'metro',
  'mexico',
  'miami',
  'mickey',
  'mid',
  'midas',
  'midday',
  'middle',
  'midst',
  'midway',
  'might',
  'mighty',
  'milan',
  'mild',
  'mildew',
  'mile',
  'milk',
  'milky',
  'mill',
  'mimic',
  'mince',
  'mind',
  'mine',
  'mini',
  'mink',
  'minor',
  'mint',
  'minus',
  'minute',
  'mirror',
  'mirth',
  'misery',
  'miss',
  'mist',
  'misty',
  'mite',
  'mix',
  'mizzle',
  'moan',
  'moat',
  'mobile',
  'mock',
  'mode',
  'model',
  'modem',
  'modern',
  'modest',
  'modify',
  'module',
  'moist',
  'molar',
  'mole',
  'molten',
  'moment',
  'monaco',
  'monday',
  'money',
  'monies',
  'monk',
  'monkey',
  'month',
  'mood',
  'moody',
  'moon',
  'moor',
  'moral',
  'morale',
  'morbid',
  'more',
  'morgue',
  'mortal',
  'mortar',
  'mosaic',
  'moscow',
  'moses',
  'mosque',
  'moss',
  'most',
  'mostly',
  'moth',
  'mother',
  'motion',
  'motive',
  'motor',
  'mould',
  'mount',
  'mourn',
  'mouse',
  'mouth',
  'move',
  'movie',
  'mrs',
  'much',
  'muck',
  'mucky',
  'mucus',
  'mud',
  'muddle',
  'muddy',
  'mule',
  'mummy',
  'munich',
  'murky',
  'murmur',
  'muscle',
  'museum',
  'music',
  'mussel',
  'must',
  'mutant',
  'mute',
  'mutiny',
  'mutter',
  'mutton',
  'mutual',
  'muzzle',
  'myopic',
  'myriad',
  'myself',
  'mystic',
  'myth',
  'nadir',
  'nail',
  'name',
  'namely',
  'nape',
  'napkin',
  'naples',
  'narrow',
  'nasal',
  'nation',
  'native',
  'nature',
  'nausea',
  'naval',
  'nave',
  'navy',
  'near',
  'nearer',
  'nearly',
  'neat',
  'neatly',
  'neck',
  'need',
  'needle',
  'needy',
  'negate',
  'nemo',
  'neon',
  'nepal',
  'nephew',
  'nerve',
  'nest',
  'neural',
  'never',
  'newark',
  'newly',
  'next',
  'nice',
  'nicely',
  'niche',
  'nickel',
  'nidor',
  'niece',
  'night',
  'nile',
  'nimble',
  'nine',
  'ninety',
  'ninth',
  'nobel',
  'noble',
  'nobody',
  'node',
  'noise',
  'noisy',
  'non',
  'none',
  'noon',
  'nor',
  'norm',
  'normal',
  'north',
  'norway',
  'nose',
  'nostoc',
  'nosy',
  'not',
  'note',
  'notice',
  'notify',
  'notion',
  'nought',
  'noun',
  'novel',
  'novice',
  'now',
  'nozzle',
  'nubere',
  'null',
  'numb',
  'number',
  'nurse',
  'nylon',
  'oak',
  'oasis',
  'oath',
  'obese',
  'obey',
  'object',
  'oblige',
  'oboe',
  'obtain',
  'occult',
  'occupy',
  'occur',
  'ocean',
  'octave',
  'odd',
  'off',
  'offend',
  'offer',
  'office',
  'offset',
  'often',
  'ohio',
  'oil',
  'oily',
  'okay',
  'old',
  'older',
  'oldest',
  'olive',
  'omega',
  'omen',
  'omit',
  'once',
  'one',
  'onion',
  'only',
  'onset',
  'onto',
  'onus',
  'onward',
  'opaque',
  'open',
  'openly',
  'opera',
  'opium',
  'oppose',
  'optic',
  'option',
  'oracle',
  'orange',
  'orbit',
  'orchid',
  'orchil',
  'ordeal',
  'order',
  'organ',
  'orient',
  'origin',
  'ornate',
  'orphan',
  'oscar',
  'oslo',
  'other',
  'otter',
  'ought',
  'ounce',
  'our',
  'out',
  'outer',
  'output',
  'outset',
  'oval',
  'oven',
  'over',
  'overt',
  'owe',
  'owing',
  'owl',
  'own',
  'owner',
  'oxford',
  'oxide',
  'oxygen',
  'oyster',
  'ozone',
  'pace',
  'pack',
  'packet',
  'pact',
  'paddle',
  'paddy',
  'pagan',
  'page',
  'paid',
  'pain',
  'paint',
  'pair',
  'palace',
  'pale',
  'palm',
  'panama',
  'panel',
  'panic',
  'papa',
  'papal',
  'paper',
  'parade',
  'parcel',
  'pardon',
  'parent',
  'paris',
  'parish',
  'park',
  'parody',
  'parrot',
  'part',
  'partly',
  'party',
  'pascal',
  'pass',
  'past',
  'paste',
  'pastel',
  'pastor',
  'pastry',
  'pat',
  'patch',
  'patent',
  'path',
  'patio',
  'patrol',
  'patron',
  'paul',
  'pause',
  'pave',
  'pay',
  'peace',
  'peach',
  'peak',
  'pear',
  'pearl',
  'pedal',
  'peel',
  'peer',
  'peking',
  'pelvic',
  'pelvis',
  'pen',
  'penal',
  'pence',
  'pencil',
  'pennon',
  'penny',
  'people',
  'pepper',
  'per',
  'perch',
  'peril',
  'perish',
  'permit',
  'person',
  'peru',
  'pest',
  'peter',
  'petrol',
  'petty',
  'phage',
  'phase',
  'philip',
  'phone',
  'photo',
  'phrase',
  'piano',
  'pick',
  'picket',
  'picnic',
  'pie',
  'piece',
  'pier',
  'pierce',
  'piety',
  'pig',
  'pigeon',
  'piggy',
  'pigsty',
  'pike',
  'pile',
  'pill',
  'pillar',
  'pillow',
  'pilot',
  'pin',
  'pinch',
  'pine',
  'pink',
  'pint',
  'pious',
  'pipe',
  'pirate',
  'piston',
  'pit',
  'pitch',
  'pity',
  'pivot',
  'pixel',
  'pizza',
  'place',
  'placid',
  'plague',
  'plaguy',
  'plain',
  'plan',
  'plane',
  'planet',
  'plank',
  'plant',
  'plasma',
  'plate',
  'play',
  'playa',
  'player',
  'plea',
  'plead',
  'please',
  'pledge',
  'plenty',
  'plenum',
  'plight',
  'plot',
  'ploy',
  'plum',
  'plump',
  'plunge',
  'plural',
  'plus',
  'plush',
  'pocket',
  'pod',
  'poem',
  'poet',
  'poetic',
  'poetry',
  'point',
  'poison',
  'poland',
  'polar',
  'pole',
  'police',
  'policy',
  'polish',
  'polite',
  'poll',
  'pollen',
  'polo',
  'pond',
  'ponder',
  'pony',
  'pool',
  'poor',
  'poorly',
  'pop',
  'pope',
  'popery',
  'poppy',
  'pore',
  'pork',
  'port',
  'portal',
  'pose',
  'posh',
  'post',
  'postal',
  'potato',
  'potent',
  'pouch',
  'pound',
  'pour',
  'powder',
  'power',
  'prague',
  'praise',
  'prate',
  'pray',
  'prayer',
  'preach',
  'prefer',
  'prefix',
  'press',
  'pretty',
  'price',
  'pride',
  'priest',
  'primal',
  'prime',
  'prince',
  'print',
  'prior',
  'prism',
  'prison',
  'privy',
  'prize',
  'probe',
  'profit',
  'prompt',
  'prone',
  'proof',
  'propel',
  'proper',
  'prose',
  'proton',
  'proud',
  'prove',
  'proven',
  'proxy',
  'prune',
  'psalm',
  'pseudo',
  'psyche',
  'pub',
  'public',
  'puff',
  'pull',
  'pulp',
  'pulpit',
  'pulsar',
  'pulse',
  'pump',
  'punch',
  'pung',
  'punish',
  'punk',
  'pupil',
  'puppet',
  'puppy',
  'pure',
  'purely',
  'purge',
  'purify',
  'purple',
  'purse',
  'pursue',
  'push',
  'pushy',
  'put',
  'putt',
  'puzzle',
  'quaint',
  'quake',
  'quarry',
  'quartz',
  'quay',
  'quebec',
  'queen',
  'query',
  'quest',
  'queue',
  'quick',
  'quid',
  'quiet',
  'quilt',
  'quirk',
  'quit',
  'quite',
  'quiver',
  'quiz',
  'quota',
  'quote',
  'rabato',
  'rabbit',
  'race',
  'racism',
  'rack',
  'racket',
  'radar',
  'radio',
  'radish',
  'radius',
  'raffle',
  'raft',
  'rage',
  'raid',
  'rail',
  'rain',
  'rainy',
  'raise',
  'rally',
  'ramp',
  'random',
  'range',
  'rank',
  'ransom',
  'rapid',
  'rare',
  'rarely',
  'rarity',
  'rash',
  'rat',
  'rate',
  'rather',
  'ratify',
  'ratio',
  'rattle',
  'rave',
  'raven',
  'raw',
  'ray',
  'razor',
  'reach',
  'react',
  'read',
  'reader',
  'ready',
  'real',
  'really',
  'realm',
  'reap',
  'rear',
  'reason',
  'rebel',
  'recall',
  'recent',
  'recess',
  'recipe',
  'reckon',
  'record',
  'recoup',
  'rector',
  'red',
  'redeem',
  'reduce',
  'reed',
  'reef',
  'reefy',
  'refer',
  'reform',
  'refuge',
  'refuse',
  'regal',
  'regard',
  'regent',
  'regime',
  'region',
  'regret',
  'reign',
  'relate',
  'relax',
  'relay',
  'relic',
  'relief',
  'relish',
  'rely',
  'remain',
  'remark',
  'remedy',
  'remind',
  'remit',
  'remote',
  'remove',
  'renal',
  'render',
  'rent',
  'rental',
  'repair',
  'repeal',
  'repeat',
  'repent',
  'repine',
  'reply',
  'report',
  'rescue',
  'resent',
  'reside',
  'resign',
  'resin',
  'resist',
  'resort',
  'rest',
  'result',
  'resume',
  'retail',
  'retain',
  'retina',
  'retire',
  'return',
  'reveal',
  'revest',
  'review',
  'revise',
  'revive',
  'revolt',
  'reward',
  'rex',
  'rhexia',
  'rhine',
  'rhino',
  'rho',
  'rhyme',
  'rhythm',
  'ribbon',
  'rice',
  'rich',
  'rick',
  'rid',
  'ride',
  'rider',
  'ridge',
  'rife',
  'rifle',
  'rift',
  'right',
  'rigid',
  'ring',
  'rinse',
  'riot',
  'ripe',
  'ripen',
  'ripple',
  'rise',
  'risk',
  'risky',
  'rite',
  'ritual',
  'ritz',
  'rival',
  'river',
  'road',
  'roar',
  'roast',
  'rob',
  'robe',
  'robert',
  'robin',
  'robot',
  'robust',
  'rock',
  'rocket',
  'rocks',
  'rocky',
  'rod',
  'rode',
  'rodent',
  'rogue',
  'role',
  'roll',
  'roman',
  'rome',
  'roof',
  'room',
  'root',
  'rope',
  'rosa',
  'rose',
  'roseau',
  'rosy',
  'rotate',
  'rotor',
  'rotten',
  'rouge',
  'rough',
  'round',
  'route',
  'rover',
  'row',
  'royal',
  'rubble',
  'ruby',
  'rudder',
  'rude',
  'rugby',
  'ruin',
  'rule',
  'ruler',
  'rumble',
  'run',
  'rune',
  'rung',
  'runway',
  'rural',
  'rush',
  'russia',
  'rust',
  'rustic',
  'rusty',
  'ruta',
  'sabe',
  'saber',
  'sack',
  'sacred',
  'sad',
  'saddle',
  'sadism',
  'sadly',
  'safari',
  'safe',
  'safely',
  'safer',
  'safety',
  'saga',
  'sage',
  'sahara',
  'said',
  'sail',
  'sailor',
  'saint',
  'sake',
  'salad',
  'salary',
  'sale',
  'saline',
  'saliva',
  'salmon',
  'saloon',
  'salt',
  'salty',
  'salute',
  'sam',
  'same',
  'sample',
  'sand',
  'sandy',
  'sane',
  'sarong',
  'sash',
  'satin',
  'satire',
  'saturn',
  'sauce',
  'saudi',
  'sauna',
  'savage',
  'save',
  'saxon',
  'say',
  'scale',
  'scalp',
  'scan',
  'scant',
  'scar',
  'scarce',
  'scare',
  'scarf',
  'scary',
  'scene',
  'scenic',
  'scent',
  'school',
  'scope',
  'score',
  'scorn',
  'scot',
  'scotch',
  'scout',
  'scrap',
  'scream',
  'screen',
  'script',
  'scroll',
  'scrub',
  'scute',
  'sea',
  'seal',
  'seam',
  'seaman',
  'search',
  'season',
  'seat',
  'second',
  'secret',
  'sect',
  'sector',
  'secure',
  'see',
  'seed',
  'seeing',
  'seek',
  'seem',
  'seize',
  'seldom',
  'select',
  'self',
  'sell',
  'seller',
  'semi',
  'senate',
  'send',
  'senile',
  'senior',
  'sense',
  'sensor',
  'sent',
  'sentry',
  'seoul',
  'sequel',
  'serene',
  'serial',
  'series',
  'sermon',
  'serum',
  'serve',
  'server',
  'set',
  'settle',
  'seven',
  'severe',
  'sewage',
  'shabby',
  'shade',
  'shadow',
  'shady',
  'shaft',
  'shaggy',
  'shah',
  'shake',
  'shaky',
  'shall',
  'sham',
  'shame',
  'shanks',
  'shape',
  'share',
  'shark',
  'sharp',
  'shawl',
  'she',
  'shear',
  'sheen',
  'sheep',
  'sheer',
  'sheet',
  'shelf',
  'shell',
  'sherry',
  'shield',
  'shift',
  'shine',
  'shiny',
  'ship',
  'shire',
  'shirt',
  'shiver',
  'shock',
  'shoe',
  'shook',
  'shop',
  'shore',
  'short',
  'shot',
  'should',
  'shout',
  'show',
  'shower',
  'shrank',
  'shrewd',
  'shrill',
  'shrimp',
  'shrine',
  'shrink',
  'shrub',
  'shrug',
  'shuha',
  'shut',
  'shy',
  'shyly',
  'side',
  'sided',
  'siege',
  'sigh',
  'sight',
  'sigma',
  'sign',
  'signal',
  'silent',
  'silk',
  'silken',
  'silky',
  'sill',
  'silly',
  'silver',
  'simian',
  'simple',
  'simply',
  'since',
  'sinful',
  'sing',
  'singer',
  'single',
  'sink',
  'sir',
  'siren',
  'sirius',
  'sister',
  'sit',
  'site',
  'six',
  'sixth',
  'sixty',
  'size',
  'sketch',
  'skill',
  'skin',
  'skinny',
  'skip',
  'skirt',
  'skull',
  'sky',
  'slab',
  'slabby',
  'slack',
  'slain',
  'slam',
  'slang',
  'slap',
  'slate',
  'slater',
  'sleek',
  'sleep',
  'sleepy',
  'sleeve',
  'slice',
  'slick',
  'slid',
  'slide',
  'slight',
  'slim',
  'slimy',
  'sling',
  'slip',
  'slit',
  'slogan',
  'slope',
  'sloppy',
  'slot',
  'slow',
  'slowly',
  'slug',
  'slum',
  'slump',
  'small',
  'smart',
  'smash',
  'smear',
  'smell',
  'smelly',
  'smelt',
  'smile',
  'smite',
  'smoke',
  'smoky',
  'smooth',
  'smug',
  'snack',
  'snail',
  'snake',
  'snap',
  'sneak',
  'snow',
  'snowy',
  'snug',
  'soak',
  'soap',
  'sober',
  'soccer',
  'social',
  'sock',
  'socket',
  'soda',
  'sodden',
  'sodium',
  'sofa',
  'soft',
  'soften',
  'softly',
  'soggy',
  'soil',
  'solar',
  'sold',
  'sole',
  'solely',
  'solemn',
  'solid',
  'solo',
  'solve',
  'somali',
  'some',
  'son',
  'sonar',
  'sonata',
  'song',
  'sonic',
  'sony',
  'soon',
  'sooner',
  'soot',
  'soothe',
  'sordid',
  'sore',
  'sorrow',
  'sorry',
  'sort',
  'soul',
  'sound',
  'soup',
  'sour',
  'source',
  'space',
  'spade',
  'spain',
  'span',
  'spare',
  'spark',
  'sparse',
  'spasm',
  'spat',
  'spate',
  'speak',
  'spear',
  'speech',
  'speed',
  'speedy',
  'spell',
  'spend',
  'sphere',
  'spice',
  'spicy',
  'spider',
  'spiky',
  'spill',
  'spin',
  'spinal',
  'spine',
  'spinus',
  'spiral',
  'spirit',
  'spite',
  'splash',
  'split',
  'spoil',
  'spoke',
  'sponge',
  'spoon',
  'sport',
  'spot',
  'spouse',
  'spout',
  'spray',
  'spread',
  'spree',
  'spring',
  'sprint',
  'spur',
  'squad',
  'square',
  'squash',
  'squat',
  'squid',
  'stab',
  'stable',
  'stack',
  'staff',
  'stage',
  'stain',
  'stair',
  'stake',
  'stale',
  'stalin',
  'stall',
  'stamp',
  'stance',
  'stand',
  'staple',
  'star',
  'starch',
  'stare',
  'stark',
  'start',
  'starve',
  'state',
  'static',
  'statue',
  'status',
  'stay',
  'stead',
  'steady',
  'steak',
  'steal',
  'steam',
  'steel',
  'steep',
  'steer',
  'stem',
  'stench',
  'step',
  'steppe',
  'stereo',
  'stern',
  'stew',
  'stick',
  'sticky',
  'stiff',
  'stifle',
  'stigma',
  'still',
  'sting',
  'stint',
  'stir',
  'stitch',
  'stock',
  'stocky',
  'stone',
  'stony',
  'stool',
  'stop',
  'store',
  'storm',
  'stormy',
  'story',
  'stot',
  'stout',
  'stove',
  'strain',
  'strait',
  'strand',
  'strap',
  'strata',
  'straw',
  'stray',
  'streak',
  'stream',
  'street',
  'stress',
  'strict',
  'stride',
  'strife',
  'strike',
  'string',
  'strip',
  'strive',
  'stroll',
  'strong',
  'stud',
  'studio',
  'study',
  'stuff',
  'stuffy',
  'stunt',
  'sturdy',
  'style',
  'submit',
  'subset',
  'subtle',
  'subtly',
  'suburb',
  'such',
  'sudan',
  'sudden',
  'sue',
  'suez',
  'suffer',
  'sugar',
  'suit',
  'suite',
  'suitor',
  'sullen',
  'sultan',
  'sum',
  'summer',
  'summit',
  'summon',
  'sun',
  'sunday',
  'sunny',
  'sunset',
  'super',
  'superb',
  'supper',
  'supple',
  'supply',
  'sure',
  'surely',
  'surf',
  'surge',
  'survey',
  'suture',
  'swamp',
  'swan',
  'swap',
  'swarm',
  'sway',
  'swear',
  'sweat',
  'sweaty',
  'sweden',
  'sweep',
  'sweet',
  'swell',
  'swift',
  'swim',
  'swine',
  'swing',
  'swirl',
  'swiss',
  'switch',
  'sword',
  'swore',
  'sydney',
  'symbol',
  'synod',
  'syntax',
  'syria',
  'syrup',
  'system',
  'table',
  'tablet',
  'tace',
  'tacit',
  'tackle',
  'tact',
  'tactic',
  'tail',
  'tailor',
  'taiwan',
  'take',
  'tale',
  'talent',
  'talk',
  'tall',
  'tally',
  'tame',
  'tandem',
  'tangle',
  'tank',
  'tap',
  'tape',
  'target',
  'tariff',
  'tart',
  'tarzan',
  'task',
  'tasset',
  'taste',
  'tasty',
  'tattoo',
  'taurus',
  'taut',
  'tavern',
  'tax',
  'taxi',
  'tea',
  'teach',
  'teak',
  'team',
  'tear',
  'tease',
  'tech',
  'tecum',
  'teeth',
  'tehran',
  'tel',
  'tell',
  'temper',
  'temple',
  'tempo',
  'tempt',
  'ten',
  'tenant',
  'tend',
  'tender',
  'tendon',
  'tenet',
  'tennis',
  'tenor',
  'tense',
  'tensor',
  'tent',
  'tenth',
  'tenure',
  'tera',
  'teresa',
  'term',
  'test',
  'texas',
  'text',
  'than',
  'thank',
  'that',
  'the',
  'their',
  'them',
  'theme',
  'then',
  'thence',
  'theory',
  'there',
  'these',
  'thesis',
  'they',
  'thick',
  'thief',
  'thigh',
  'thin',
  'thing',
  'think',
  'third',
  'thirst',
  'thirty',
  'this',
  'thomas',
  'thorn',
  'those',
  'though',
  'thread',
  'threat',
  'three',
  'thrill',
  'thrive',
  'throat',
  'throne',
  'throng',
  'throw',
  'thrust',
  'thud',
  'thug',
  'thumb',
  'thump',
  'thus',
  'thyme',
  'tibet',
  'tick',
  'ticket',
  'tidal',
  'tide',
  'tidy',
  'tie',
  'tier',
  'tiger',
  'tight',
  'tile',
  'tiling',
  'till',
  'tilt',
  'timber',
  'time',
  'timid',
  'tin',
  'tiny',
  'tip',
  'tissue',
  'title',
  'toad',
  'toast',
  'today',
  'token',
  'tokyo',
  'told',
  'toll',
  'tom',
  'tomato',
  'tomb',
  'tonal',
  'tone',
  'tonic',
  'too',
  'took',
  'tool',
  'tooth',
  'top',
  'topaz',
  'tophet',
  'topic',
  'torch',
  'torque',
  'torso',
  'tort',
  'toss',
  'total',
  'totem',
  'touch',
  'tough',
  'tour',
  'toward',
  'towel',
  'tower',
  'town',
  'toxic',
  'toxin',
  'trace',
  'track',
  'tract',
  'trade',
  'tragic',
  'trail',
  'train',
  'trait',
  'tram',
  'trance',
  'trap',
  'trauma',
  'travel',
  'tray',
  'tread',
  'treat',
  'treaty',
  'treble',
  'tree',
  'trek',
  'tremor',
  'trench',
  'trend',
  'trendy',
  'trial',
  'tribal',
  'tribe',
  'trick',
  'tricky',
  'tried',
  'trifle',
  'trim',
  'trio',
  'trip',
  'triple',
  'troop',
  'trophy',
  'trot',
  'trough',
  'trout',
  'truce',
  'truck',
  'true',
  'truly',
  'trunk',
  'trust',
  'truth',
  'try',
  'tsar',
  'tube',
  'tulle',
  'tumble',
  'tuna',
  'tundra',
  'tune',
  'tung',
  'tunic',
  'tunis',
  'tunnel',
  'turban',
  'turf',
  'turk',
  'turkey',
  'turn',
  'turtle',
  'tutor',
  'tweed',
  'twelve',
  'twenty',
  'twice',
  'twin',
  'twist',
  'two',
  'tycoon',
  'tying',
  'type',
  'tyrant',
  'uganda',
  'ugly',
  'ulcer',
  'ultra',
  'umpire',
  'unable',
  'uncle',
  'under',
  'uneasy',
  'unfair',
  'unify',
  'union',
  'unique',
  'unit',
  'unite',
  'unity',
  'unkind',
  'unlike',
  'unrest',
  'unruly',
  'unship',
  'until',
  'unwary',
  'update',
  'upheld',
  'uphill',
  'uphold',
  'upon',
  'uproar',
  'upset',
  'upshot',
  'uptake',
  'upturn',
  'upward',
  'urban',
  'urge',
  'urgent',
  'urging',
  'usable',
  'usage',
  'use',
  'useful',
  'user',
  'usual',
  'utmost',
  'utter',
  'vacant',
  'vacuum',
  'vague',
  'vain',
  'valet',
  'valid',
  'valley',
  'value',
  'valve',
  'van',
  'vanish',
  'vanity',
  'vary',
  'vase',
  'vast',
  'vat',
  'vault',
  'vector',
  'vedic',
  'veil',
  'vein',
  'velvet',
  'vendor',
  'veneer',
  'venice',
  'venom',
  'vent',
  'venue',
  'venus',
  'verb',
  'verbal',
  'verge',
  'verify',
  'verity',
  'verse',
  'versus',
  'very',
  'vessel',
  'vest',
  'veto',
  'vex',
  'via',
  'viable',
  'vicar',
  'vice',
  'victim',
  'victor',
  'video',
  'vienna',
  'view',
  'vigil',
  'vigor',
  'viking',
  'vile',
  'villa',
  'vine',
  'vinyl',
  'viola',
  'violet',
  'violin',
  'viral',
  'virgo',
  'virtue',
  'virus',
  'visa',
  'vision',
  'visit',
  'visual',
  'vitae',
  'vital',
  'vivid',
  'vocal',
  'vodka',
  'vogue',
  'voice',
  'void',
  'volley',
  'volume',
  'vote',
  'vowel',
  'voyage',
  'vulgar',
  'wade',
  'wage',
  'waist',
  'wait',
  'waiter',
  'wake',
  'walk',
  'walker',
  'wall',
  'wallet',
  'walnut',
  'wander',
  'want',
  'war',
  'warden',
  'warm',
  'warmth',
  'warn',
  'warp',
  'warsaw',
  'wary',
  'was',
  'wash',
  'wasp',
  'waste',
  'watch',
  'water',
  'watery',
  'wave',
  'way',
  'weak',
  'weaken',
  'wealth',
  'wear',
  'weary',
  'wedge',
  'wee',
  'weed',
  'week',
  'weekly',
  'weep',
  'weight',
  'weird',
  'well',
  'were',
  'west',
  'wet',
  'whale',
  'wharf',
  'what',
  'wheat',
  'wheel',
  'wheeze',
  'wheezy',
  'when',
  'whence',
  'where',
  'which',
  'whiff',
  'whig',
  'while',
  'whim',
  'whip',
  'whisky',
  'white',
  'who',
  'whole',
  'wholly',
  'whom',
  'whose',
  'why',
  'wide',
  'widely',
  'widen',
  'wider',
  'widow',
  'width',
  'wife',
  'wild',
  'wildly',
  'wilful',
  'will',
  'willow',
  'win',
  'wind',
  'window',
  'windy',
  'wine',
  'winery',
  'wing',
  'wink',
  'winner',
  'winter',
  'wipe',
  'wire',
  'wisdom',
  'wise',
  'wish',
  'wit',
  'witch',
  'with',
  'within',
  'witty',
  'wizard',
  'woke',
  'wolf',
  'wolves',
  'woman',
  'womb',
  'won',
  'wonder',
  'wood',
  'wooden',
  'woods',
  'woody',
  'wool',
  'word',
  'work',
  'worker',
  'world',
  'worm',
  'worry',
  'worse',
  'worst',
  'worth',
  'worthy',
  'would',
  'wound',
  'wrap',
  'wrath',
  'wreath',
  'wreck',
  'wren',
  'wright',
  'wrist',
  'writ',
  'write',
  'writer',
  'wrong',
  'xerox',
  'yacht',
  'yager',
  'yale',
  'yard',
  'yarn',
  'yeah',
  'year',
  'yeast',
  'yellow',
  'yemen',
  'yet',
  'yield',
  'yogurt',
  'yokel',
  'yolk',
  'york',
  'you',
  'young',
  'your',
  'youth',
  'zaire',
  'zeal',
  'zebra',
  'zenith',
  'zero',
  'zigzag',
  'zinc',
  'zing',
  'zipper',
  'zombie',
  'zone',
  'zurich',
];

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function shake128(out, msg) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function shake256(out, msg) {
  const hash = sha3Shake256(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function sha256(out, msg) {
  const hashOut = sha256$1(msg);
  for (let i = 0, h = 0; i < out.length && h < hashOut.length; i++, h++) {
    out.set([hashOut[h]], i);
  }
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} typeValue
 */
function setType(addr, typeValue) {
  addr.set([typeValue], 3);
  for (let i = 4; i < 8; i++) {
    addr.set([0], i);
  }
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} lTree
 */
function setLTreeAddr(addr, lTree) {
  addr.set([lTree], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} ots
 */
function setOTSAddr(addr, ots) {
  addr.set([ots], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 */
function setChainAddr(addr, chain) {
  addr.set([chain], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 */
function setHashAddr(addr, hash) {
  addr.set([hash], 6);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 */
function setKeyAndMask(addr, keyAndMask) {
  addr.set([keyAndMask], 7);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeHeight
 */
function setTreeHeight(addr, treeHeight) {
  addr.set([treeHeight], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeIndex
 */
function setTreeIndex(addr, treeIndex) {
  addr.set([treeIndex], 6);
}

/** @returns Number */
function getEndian() {
  const buffer = new ArrayBuffer(2);
  const uint16View = new Uint16Array(buffer);
  const uint8View = new Uint8Array(buffer);
  uint16View[0] = 0xabcd;
  if (uint8View[0] === 0xcd && uint8View[1] === 0xab) {
    return ENDIAN.LITTLE;
  }
  if (uint8View[0] === 0xab && uint8View[1] === 0xcd) {
    return ENDIAN.BIG;
  }
  throw new Error('Could not determine native endian.');
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteLittleEndian(out, input, bytes) {
  let inValue = input;
  for (let i = bytes - 1; i >= 0; i--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteBigEndian(out, input, bytes) {
  let inValue = input;
  for (let i = 0; i < bytes; i++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
function addrToByte(out, addr, getEndianFunc = getEndian) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        toByteLittleEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        toByteBigEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    default:
      throw new Error('Invalid Endian');
  }
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
function binToMnemonic(input) {
  if (input.length % 3 !== 0) {
    throw new Error('byte count needs to be a multiple of 3');
  }

  const buf = [];
  const separator = ' ';
  for (let nibble = 0; nibble < input.length * 2; nibble += 3) {
    const p = nibble >>> 1;
    const [b1] = new Uint32Array([input[p]]);
    let [b2] = new Uint32Array([0]);
    if (p + 1 < input.length) {
      [b2] = new Uint32Array([input[p + 1]]);
    }
    let [idx] = new Uint32Array([0]);
    if (nibble % 2 === 0) {
      idx = (b1 << 4) + (b2 >>> 4);
    } else {
      idx = ((b1 & 0x0f) << 8) + b2;
    }
    try {
      buf.push(WORD_LIST[idx]);
    } catch (error) {
      throw new Error(`ExtendedSeedBinToMnemonic error ${error?.message}`);
    }
  }

  return buf.join(separator);
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
function seedBinToMnemonic(input) {
  if (input.length !== COMMON.SEED_SIZE) {
    throw new Error(`input should be an array of size ${COMMON.SEED_SIZE}`);
  }

  return binToMnemonic(input);
}

/**
 * @param {Uint8Arrayany} input
 * @returns {string}
 */
function extendedSeedBinToMnemonic(input) {
  if (input.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`input should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  return binToMnemonic(input);
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
function mnemonicToBin(mnemonic) {
  const mnemonicWords = mnemonic.split(' ');
  const wordCount = mnemonicWords.length;
  if (wordCount % 2 !== 0) {
    throw new Error(`Word count = ${wordCount} must be even`);
  }

  const wordLookup = {};

  for (let i = 0; i < WORD_LIST.length; i++) {
    wordLookup[WORD_LIST[i]] = i;
  }

  const result = new Uint8Array((wordCount * 15) / 10);
  let current = 0;
  let buffering = 0;
  let resultIndex = 0;
  for (let i = 0; i < wordCount; i++) {
    const w = mnemonicWords[i];
    const found = w in wordLookup;
    if (!found) {
      throw new Error('Invalid word in mnemonic');
    }
    const value = wordLookup[w];

    buffering += 3;
    current = (current << 12) + value;
    while (buffering > 2) {
      const shift = 4 * (buffering - 2);
      const mask = (1 << shift) - 1;
      const tmp = current >>> shift;
      buffering -= 2;
      current &= mask;
      result.set([tmp], resultIndex);
      resultIndex++;
    }
  }

  if (buffering > 0) {
    result.set([current & 0xff], resultIndex);
    resultIndex++;
  }

  return result;
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
function mnemonicToSeedBin(mnemonic) {
  const output = mnemonicToBin(mnemonic);

  if (output.length !== COMMON.SEED_SIZE) {
    throw new Error('Unexpected MnemonicToSeedBin output size');
  }

  const sizedOutput = new Uint8Array(COMMON.SEED_SIZE);
  for (
    let sizedOutputIndex = 0, outputIndex = 0;
    sizedOutputIndex < sizedOutput.length && outputIndex < output.length;
    sizedOutputIndex++, outputIndex++
  ) {
    sizedOutput.set([output[outputIndex]], sizedOutputIndex);
  }

  return sizedOutput;
}

/**
 * @param {string} mnemonic
 * @returns {Uint8Array}
 */
function mnemonicToExtendedSeedBin(mnemonic) {
  const output = mnemonicToBin(mnemonic);

  if (output.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error('Unexpected MnemonicToExtendedSeedBin output size');
  }

  const sizedOutput = new Uint8Array(COMMON.EXTENDED_SEED_SIZE);
  for (
    let sizedOutputIndex = 0, outputIndex = 0;
    sizedOutputIndex < sizedOutput.length && outputIndex < output.length;
    sizedOutputIndex++, outputIndex++
  ) {
    sizedOutput.set([output[outputIndex]], sizedOutputIndex);
  }

  return sizedOutput;
}

/// <reference path="typedefs.js" />


/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} typeValue
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} inLen
 * @param {Uint32Array[number]} n
 */
function coreHash(hashFunction, out, typeValue, key, keyLen, input, inLen, n) {
  const buf = new Uint8Array(inLen + n + keyLen);
  toByteLittleEndian(buf, typeValue, n);
  for (let i = 0; i < keyLen; i++) {
    buf.set([key[i]], i + n);
  }
  for (let i = 0; i < inLen; i++) {
    buf.set([input[i]], keyLen + n + i);
  }

  switch (hashFunction) {
    case HASH_FUNCTION.SHA2_256:
      sha256(out, buf);
      break;
    case HASH_FUNCTION.SHAKE_128:
      shake128(out, buf);
      break;
    case HASH_FUNCTION.SHAKE_256:
      shake256(out, buf);
      break;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 */
function prf(hashFunction, out, input, key, keyLen) {
  coreHash(hashFunction, out, 3, key, keyLen, input, 32, keyLen);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
function hashH(hashFunction, out, input, pubSeed, addr, n) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buf = new Uint8Array(2 * n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(2 * n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask.subarray(0, n), byteAddr, pubSeed, n);
  setKeyAndMask(addr, 2);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask.subarray(n, n + n), byteAddr, pubSeed, n);
  for (let i = 0; i < 2 * n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 1, key, n, buf, 2 * n, n);
}

/// <reference path="typedefs.js" />

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 */
function getSeed(hashFunction, seed, skSeed, n, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const bytes = new Uint8Array(32);

  setChainAddr(addr, 0);
  setHashAddr(addr, 0);
  setKeyAndMask(addr, 0);

  addrToByte(bytes, addr);
  prf(hashFunction, seed, bytes, skSeed, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} outSeeds
 * @param {Uint8Array} inSeeds
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} len
 */
function expandSeed(hashFunction, outSeeds, inSeeds, n, len) {
  const ctr = new Uint8Array(32);
  for (let i = 0; i < len; i++) {
    toByteLittleEndian(ctr, i, 32);
    prf(hashFunction, outSeeds.subarray(i * n, i * n + n), ctr, inSeeds, n);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
function hashF(hashFunction, out, input, pubSeed, addr, n) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buf = new Uint8Array(n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n);

  for (let i = 0; i < n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 0, key, n, buf, n, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} start
 * @param {Uint32Array[number]} steps
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function genChain(hashFunction, out, input, start, steps, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  for (let i = 0; i < params.n; i++) {
    out.set([input[i]], i);
  }

  for (let i = start; i < start + steps && i < params.w; i++) {
    setHashAddr(addr, i);
    hashF(hashFunction, out, out, pubSeed, addr, params.n);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {WOTSParams} wOTSParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function wOTSPKGen(hashFunction, pk, sk, wOTSParams, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  expandSeed(hashFunction, pk, sk, wOTSParams.n, wOTSParams.len);
  for (let i = 0; i < wOTSParams.len; i++) {
    setChainAddr(addr, i);
    const pkStartOffset = i * wOTSParams.n;
    genChain(
      hashFunction,
      pk.subarray(pkStartOffset, pkStartOffset + wOTSParams.n),
      pk.subarray(pkStartOffset, pkStartOffset + wOTSParams.n),
      0,
      wOTSParams.w - 1,
      wOTSParams,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} params
 * @param {Uint8Array} leaf
 * @param {Uint8Array} wotsPK
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function lTree(hashFunction, params, leaf, wotsPK, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  let l = params.len;
  const { n } = params;

  let [height] = new Uint32Array([0]);
  let [bound] = new Uint32Array([0]);

  setTreeHeight(addr, height);
  while (l > 1) {
    bound = l >>> 1;
    for (let i = 0; i < bound; i++) {
      setTreeIndex(addr, i);
      const outStartOffset = i * n;
      const inStartOffset = i * 2 * n;
      hashH(
        hashFunction,
        wotsPK.subarray(outStartOffset, outStartOffset + n),
        wotsPK.subarray(inStartOffset, inStartOffset + 2 * n),
        pubSeed,
        addr,
        n
      );
    }
    if (l % 2 === 1) {
      const destStartOffset = (l >>> 1) * n;
      const srcStartOffset = (l - 1) * n;
      for (
        let destIndex = destStartOffset, srcIndex = srcStartOffset;
        destIndex < destStartOffset + n && srcIndex < srcStartOffset + n;
        destIndex++, srcIndex++
      ) {
        wotsPK.set([wotsPK[srcIndex]], destIndex);
      }
      l = (l >>> 1) + 1;
    } else {
      l >>>= 1;
    }
    height++;
    setTreeHeight(addr, height);
  }
  leaf.set(wotsPK.subarray(0, n));
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} leaf
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} lTreeAddr
 * @param {Uint32Array} otsAddr
 */
function genLeafWOTS(hashFunction, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr) {
  const seed = new Uint8Array(xmssParams.n);
  const pk = new Uint8Array(xmssParams.wotsParams.keySize);

  getSeed(hashFunction, seed, skSeed, xmssParams.n, otsAddr);
  wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr);
  lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} node
 * @param {Uint32Array[number]} index
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function treeHashSetup(hashFunction, node, index, bdsState, skSeed, xmssParams, pubSeed, addr) {
  const { n, h, k } = xmssParams;

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  const lastNode = index + (1 << h);

  const bound = h - k;
  const stack = new Uint8Array((h + 1) * n);
  const stackLevels = new Uint32Array(h + 1);
  let stackOffset = new Uint32Array([0])[0];
  let nodeH = new Uint32Array([0])[0];

  const bdsState1 = bdsState;
  for (let i = 0; i < bound; i++) {
    bdsState1.treeHash[i].h = i;
    bdsState1.treeHash[i].completed = 1;
    bdsState1.treeHash[i].stackUsage = 0;
  }

  for (let i = 0, index1 = index; index1 < lastNode; i++, index1++) {
    setLTreeAddr(lTreeAddr, index1);
    setOTSAddr(otsAddr, index1);

    genLeafWOTS(
      hashFunction,
      stack.subarray(stackOffset * n, stackOffset * n + n),
      skSeed,
      xmssParams,
      pubSeed,
      lTreeAddr,
      otsAddr
    );

    stackLevels.set([0], stackOffset);
    stackOffset++;
    if (h - k > 0 && i === 3) {
      bdsState1.treeHash[0].node.set(stack.subarray(stackOffset * n, stackOffset * n + n));
    }
    while (stackOffset > 1 && stackLevels[stackOffset - 1] === stackLevels[stackOffset - 2]) {
      nodeH = stackLevels[stackOffset - 1];
      if (i >>> nodeH === 1) {
        const authStart = nodeH * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let authIndex = authStart, stackIndex = stackStart;
          authIndex < authStart + n && stackIndex < stackStart + n;
          authIndex++, stackIndex++
        ) {
          bdsState1.auth.set([stack[stackIndex]], authIndex);
        }
      } else if (nodeH < h - k && i >>> nodeH === 3) {
        const stackStart = (stackOffset - 1) * n;
        bdsState1.treeHash[nodeH].node.set(stack.subarray(stackStart, stackStart + n));
      } else if (nodeH >= h - k) {
        const retainStart = ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >>> nodeH) - 3) >>> 1)) * n;
        const stackStart = (stackOffset - 1) * n;
        for (
          let retainIndex = retainStart, stackIndex = stackStart;
          retainIndex < retainStart + n && stackIndex < stackStart + n;
          retainIndex++, stackIndex++
        ) {
          bdsState1.retain.set([stack[stackIndex]], retainIndex);
        }
      }
      setTreeHeight(nodeAddr, stackLevels[stackOffset - 1]);
      setTreeIndex(nodeAddr, index1 >>> (stackLevels[stackOffset - 1] + 1));
      const stackStart = (stackOffset - 2) * n;

      hashH(
        hashFunction,
        stack.subarray(stackStart, stackStart + n),
        stack.subarray(stackStart, stackStart + 2 * n),
        pubSeed,
        nodeAddr,
        n
      );

      stackLevels[stackOffset - 2]++;
      stackOffset--;
    }
  }
  node.set(stack.subarray(0, n));
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} seed
 */
function XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed) {
  if (xmssParams.h % 2 === 1) {
    throw new Error('Not a valid h, only even numbers supported! Try again with an even number');
  }

  const { n } = xmssParams;

  sk.set([0, 0, 0, 0]);

  const randombits = new Uint8Array(3 * n);

  shake256(randombits, seed);

  const rnd = 96;
  const pks = new Uint32Array([32])[0];
  sk.set(randombits.subarray(0, rnd), 4);
  for (let pkIndex = n, skIndex = 4 + 2 * n; pkIndex < pk.length && skIndex < 4 + 2 * n + pks; pkIndex++, skIndex++) {
    pk.set([sk[skIndex]], pkIndex);
  }

  const addr = new Uint32Array(8);
  treeHashSetup(
    hashFunction,
    pk,
    0,
    bdsState,
    sk.subarray(4, 4 + n),
    xmssParams,
    sk.subarray(4 + 2 * n, 4 + 2 * n + n),
    addr
  );

  for (let skIndex = 4 + 3 * n, pkIndex = 0; skIndex < sk.length && pkIndex < pks; skIndex++, pkIndex++) {
    sk.set([pk[pkIndex]], skIndex);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {TreeHashInst} treeHash
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function treeHashUpdate(hashFunction, treeHash, bdsState, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const treeHash1 = treeHash;
  const bdsState1 = bdsState;

  const { n } = params;

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  setLTreeAddr(lTreeAddr, treeHash1.nextIdx);
  setOTSAddr(otsAddr, treeHash1.nextIdx);

  const nodeBuffer = new Uint8Array(2 * n);
  let [nodeHeight] = new Uint32Array([0]);

  genLeafWOTS(hashFunction, nodeBuffer, skSeed, params, pubSeed, lTreeAddr, otsAddr);

  while (treeHash1.stackUsage > 0 && bdsState1.stackLevels[bdsState1.stackOffset - 1] === nodeHeight) {
    for (let i = n, j = 0; i < n + n && j < n; i++, j++) {
      nodeBuffer.set([nodeBuffer[j]], i);
    }
    const srcOffset = (bdsState1.stackOffset - 1) * n;
    for (
      let nodeIndex = 0, stackIndex = srcOffset;
      nodeIndex < n && stackIndex < srcOffset + n;
      nodeIndex++, stackIndex++
    ) {
      nodeBuffer.set([bdsState1.stack[stackIndex]], nodeIndex);
    }
    setTreeHeight(nodeAddr, nodeHeight);
    setTreeIndex(nodeAddr, treeHash1.nextIdx >>> (nodeHeight + 1));
    hashH(hashFunction, nodeBuffer.subarray(0, n), nodeBuffer, pubSeed, nodeAddr, n);
    nodeHeight++;
    treeHash1.stackUsage--;
    bdsState1.stackOffset--;
  }

  if (nodeHeight === treeHash1.h) {
    treeHash1.node.set(nodeBuffer.subarray(0, n));
    treeHash1.completed = 1;
  } else {
    const destOffset = bdsState1.stackOffset * n;
    for (
      let stackIndex = destOffset, nodeIndex = 0;
      stackIndex < destOffset + n && nodeIndex < n;
      stackIndex++, nodeIndex++
    ) {
      bdsState1.stack.set([nodeBuffer[nodeIndex]], stackIndex);
    }
    treeHash1.stackUsage++;
    bdsState1.stackLevels.set([nodeHeight], bdsState1.stackOffset);
    bdsState1.stackOffset++;
    treeHash1.nextIdx++;
  }
}

/**
 * @param {BDSState} state
 * @param {XMSSParams} params
 * @param {TreeHashInst} treeHash
 * @returns {Uint8Array[number]}
 */
function treeHashMinHeightOnStack(state, params, treeHash) {
  let r = params.h;
  for (let i = 0; i < treeHash.stackUsage; i++) {
    const stackLevelOffset = state.stackLevels[state.stackOffset - i - 1];
    if (stackLevelOffset < r) {
      r = stackLevelOffset;
    }
  }
  return r;
}

/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} updates
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @returns {Uint32Array[number]}
 */
function bdsTreeHashUpdate(hashFunction, bdsState, updates, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const { h, k } = params;
  let [used] = new Uint32Array([0]);
  let [lMin] = new Uint32Array([0]);
  let [level] = new Uint32Array([0]);
  let [low] = new Uint32Array([0]);

  for (let j = 0; j < updates; j++) {
    lMin = h;
    level = h - k;
    for (let i = 0; i < h - k; i++) {
      if (bdsState.treeHash[i].completed === 1) {
        low = h;
      } else if (bdsState.treeHash[i].stackUsage === 0) {
        low = i;
      } else {
        low = treeHashMinHeightOnStack(bdsState, params, bdsState.treeHash[i]);
      }
      if (low < lMin) {
        level = i;
        lMin = low;
      }
    }
    if (level === h - k) {
      break;
    }
    treeHashUpdate(hashFunction, bdsState.treeHash[level], bdsState, skSeed, params, pubSeed, addr);
    used++;
  }

  return updates - used;
}

/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function bdsRound(hashFunction, bdsState, leafIdx, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const bdsState1 = bdsState;
  const { n, h, k } = params;

  let tau = h;
  const buf = new Uint8Array(2 * n);

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  for (let i = 0; i < h; i++) {
    if ((leafIdx >>> i) % 2 === 0) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    let srcOffset = (tau - 1) * n;
    for (let bufIndex = 0, authIndex = srcOffset; bufIndex < n && authIndex < srcOffset + n; bufIndex++, authIndex++) {
      buf.set([bdsState1.auth[authIndex]], bufIndex);
    }

    srcOffset = ((tau - 1) >>> 1) * n;
    for (
      let bufIndex = n, keepIndex = srcOffset;
      bufIndex < 2 * n && keepIndex < srcOffset + n;
      bufIndex++, keepIndex++
    ) {
      buf.set([bdsState1.keep[keepIndex]], bufIndex);
    }
  }

  if (((leafIdx >>> (tau + 1)) & 1) === 0 && tau < h - 1) {
    const destOffset = (tau >>> 1) * n;
    const srcOffset = tau * n;
    for (
      let keepIndex = destOffset, authIndex = srcOffset;
      keepIndex < destOffset + n && authIndex < srcOffset + n;
      keepIndex++, authIndex++
    ) {
      bdsState1.keep.set([bdsState1.auth[authIndex]], keepIndex);
    }
  }

  if (tau === 0) {
    setLTreeAddr(lTreeAddr, leafIdx);
    setOTSAddr(otsAddr, leafIdx);
    genLeafWOTS(hashFunction, bdsState1.auth.subarray(0, n), skSeed, params, pubSeed, lTreeAddr, otsAddr);
  } else {
    setTreeHeight(nodeAddr, tau - 1);
    setTreeIndex(nodeAddr, leafIdx >>> tau);
    hashH(hashFunction, bdsState1.auth.subarray(tau * n, tau * n + n), buf, pubSeed, nodeAddr, n);
    for (let i = 0; i < tau; i++) {
      if (i < h - k) {
        for (let authIndex = i * n, nodeIndex = 0; authIndex < i * n + n && nodeIndex < n; authIndex++, nodeIndex++) {
          bdsState1.auth.set([bdsState1.treeHash[i].node[nodeIndex]], authIndex);
        }
      } else {
        const offset = (1 << (h - 1 - i)) + i - h;
        const rowIdx = ((leafIdx >>> i) - 1) >>> 1;
        const srcOffset = (offset + rowIdx) * n;
        for (
          let authIndex = i * n, retainIndex = srcOffset;
          authIndex < i * n + n && retainIndex < srcOffset + n;
          authIndex++, retainIndex++
        ) {
          bdsState1.auth.set([bdsState1.retain[retainIndex]], authIndex);
        }
      }
    }

    let compareValue = h - k;
    if (tau < h - k) {
      compareValue = tau;
    }
    for (let i = 0; i < compareValue; i++) {
      const startIdx = leafIdx + 1 + 3 * (1 << i);
      if (startIdx < 1 << h) {
        bdsState1.treeHash[i].h = i;
        bdsState1.treeHash[i].nextIdx = startIdx;
        bdsState1.treeHash[i].completed = 0;
        bdsState1.treeHash[i].stackUsage = 0;
      }
    }
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} newIdx
 * @returns {Uint32Array[number]}
 */
function xmssFastUpdate(hashFunction, params, sk, bdsState, newIdx) {
  const [numElems] = new Uint32Array([1 << params.h]);
  const currentIdx =
    (new Uint32Array([sk[0]])[0] << 24) |
    (new Uint32Array([sk[1]])[0] << 16) |
    (new Uint32Array([sk[2]])[0] << 8) |
    new Uint32Array([sk[3]])[0];

  if (newIdx >= numElems) {
    throw new Error('Index too high');
  }
  if (newIdx < currentIdx) {
    throw new Error('Cannot rewind');
  }

  const skSeed = new Uint8Array(params.n);
  skSeed.set(sk.subarray(4, 4 + params.n));

  const startOffset = 4 + 2 * 32;
  const pubSeed = new Uint8Array(params.n);
  for (
    let pubSeedIndex = 0, skIndex = startOffset;
    pubSeedIndex < 32 && skIndex < startOffset + 32;
    pubSeedIndex++, skIndex++
  ) {
    pubSeed.set([sk[skIndex]], pubSeedIndex);
  }

  const otsAddr = new Uint32Array(8);

  for (let i = currentIdx; i < newIdx; i++) {
    if (i >= numElems) {
      return -1;
    }
    bdsRound(hashFunction, bdsState, i, skSeed, params, pubSeed, otsAddr);
    bdsTreeHashUpdate(hashFunction, bdsState, (params.h - params.k) >>> 1, skSeed, params, pubSeed, otsAddr);
  }

  sk.set(new Uint8Array([(newIdx >>> 24) & 0xff, (newIdx >>> 16) & 0xff, (newIdx >>> 8) & 0xff, newIdx & 0xff]));

  return 0;
}

/// <reference path="typedefs.js" />


/**
 * @param {Uint32Array[number]} keySize
 * @returns {Uint32Array[number]}
 */
function calculateSignatureBaseSize(keySize) {
  return 4 + 32 + keySize;
}

/**
 * @param {XMSSParams} params
 * @returns {Uint32Array[number]}
 */
function getSignatureSize(params) {
  const signatureBaseSize = calculateSignatureBaseSize(params.wotsParams.keySize);
  return signatureBaseSize + params.h * 32;
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} n
 * @returns {{ error: string }}
 */
function hMsg(hashFunction, out, input, key, n) {
  if (key.length !== 3 * n) {
    return { error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.` };
  }
  coreHash(hashFunction, out, 2, key, key.length, input, input.length, n);
  return { error: null };
}

/**
 * @param {Uint8Array} output
 * @param {Uint32Array[number]} outputLen
 * @param {Uint8Array} input
 * @param {WOTSParams} params
 */
function calcBaseW(output, outputLen, input, params) {
  let inIndex = 0;
  let outIndex = 0;
  let [total] = new Uint32Array([0]);
  let [bits] = new Uint32Array([0]);

  for (let consumed = 0; consumed < outputLen; consumed++) {
    if (bits === 0) {
      [total] = new Uint32Array([input[inIndex]]);
      inIndex++;
      [bits] = new Uint32Array([bits + 8]);
    }
    [bits] = new Uint32Array([bits - params.logW]);
    output.set([new Uint8Array([(total >>> bits) & (params.w - 1)])[0]], outIndex);
    outIndex++;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint8Array} addr
 */
function wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error(`addr should be an array of size 8`);
  }

  const baseW = new Uint8Array(params.len);
  let [csum] = new Uint32Array([0]);

  calcBaseW(baseW, params.len1, msg, params);

  for (let i = 0; i < params.len1; i++) {
    csum += params.w - 1 - new Uint32Array([baseW[i]])[0];
  }

  csum <<= 8 - ((params.len2 * params.logW) % 8);

  const len2Bytes = (params.len2 * params.logW + 7) / 8;

  const cSumBytes = new Uint8Array(len2Bytes);
  toByteLittleEndian(cSumBytes, csum, len2Bytes);

  const cSumBaseW = new Uint8Array(params.len2);

  calcBaseW(cSumBaseW, params.len2, cSumBytes, params);

  for (let i = 0; i < params.len2; i++) {
    baseW.set([cSumBaseW[i]], params.len1 + i);
  }

  expandSeed(hashFunction, sig, sk, params.n, params.len);

  for (let i = 0; i < params.len; i++) {
    setChainAddr(addr, i);
    const offset = i * params.n;
    genChain(
      hashFunction,
      sig.subarray(offset, offset + params.n),
      sig.subarray(offset, offset + params.n),
      0,
      new Uint32Array([baseW[i]])[0],
      params,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} message
 * @returns {SignatureReturnType}
 */
function xmssFastSignMessage(hashFunction, params, sk, bdsState, message) {
  const { n } = params;

  const [idx] = new Uint32Array([
    (new Uint32Array([sk[0]])[0] << 24) |
      (new Uint32Array([sk[1]])[0] << 16) |
      (new Uint32Array([sk[2]])[0] << 8) |
      new Uint32Array([sk[3]])[0],
  ]);

  const skSeed = new Uint8Array(n);
  for (let skSeedIndex = 0, skIndex = 4; skSeedIndex < skSeed.length && skIndex < 4 + n; skSeedIndex++, skIndex++) {
    skSeed.set([sk[skIndex]], skSeedIndex);
  }
  const skPRF = new Uint8Array(n);
  for (let skPrfIndex = 0, skIndex = 4 + n; skPrfIndex < skPRF.length && skIndex < 4 + n + n; skPrfIndex++, skIndex++) {
    skPRF.set([sk[skIndex]], skPrfIndex);
  }
  const pubSeed = new Uint8Array(n);
  for (
    let pubSeedIndex = 0, skIndex = 4 + 2 * n;
    pubSeedIndex < pubSeed.length && skIndex < 4 + 2 * n + n;
    pubSeedIndex++, skIndex++
  ) {
    pubSeed.set([sk[skIndex]], pubSeedIndex);
  }

  const idxBytes32 = new Uint8Array(32);
  toByteLittleEndian(idxBytes32, idx, 32);

  const hashKey = new Uint8Array(3 * n);

  sk.set([
    new Uint8Array([((idx + 1) >>> 24) & 0xff])[0],
    new Uint8Array([((idx + 1) >>> 16) & 0xff])[0],
    new Uint8Array([((idx + 1) >>> 8) & 0xff])[0],
    new Uint8Array([(idx + 1) & 0xff])[0],
  ]);

  const R = new Uint8Array(n);
  const otsAddr = new Uint32Array(8);

  prf(hashFunction, R, idxBytes32, skPRF, n);
  for (let hashKeyIndex = 0, rIndex = 0; hashKeyIndex < n && rIndex < R.length; hashKeyIndex++, rIndex++) {
    hashKey.set([R[rIndex]], hashKeyIndex);
  }
  for (
    let hashKeyIndex = n, skIndex = 4 + 3 * n;
    hashKeyIndex < n + n && skIndex < 4 + 3 * n + n;
    hashKeyIndex++, skIndex++
  ) {
    hashKey.set([sk[skIndex]], hashKeyIndex);
  }
  toByteLittleEndian(hashKey.subarray(2 * n, 2 * n + n), idx, n);
  const msgHash = new Uint8Array(n);
  const { error } = hMsg(hashFunction, msgHash, message, hashKey, n);
  if (error !== null) {
    return { sigMsg: null, error };
  }
  let [sigMsgLen] = new Uint32Array([0]);
  const sigMsg = new Uint8Array(getSignatureSize(params));
  sigMsg.set([
    new Uint8Array([(idx >>> 24) & 0xff])[0],
    new Uint8Array([(idx >>> 16) & 0xff])[0],
    new Uint8Array([(idx >>> 8) & 0xff])[0],
    new Uint8Array([idx & 0xff])[0],
  ]);

  sigMsgLen += 4;
  for (let i = 0; i < n; i++) {
    sigMsg.set([R[i]], sigMsgLen + i);
  }

  sigMsgLen += n;

  setType(otsAddr, 0);
  setOTSAddr(otsAddr, idx);

  const otsSeed = new Uint8Array(n);
  getSeed(hashFunction, otsSeed, skSeed, n, otsAddr);

  wotsSign(hashFunction, sigMsg.subarray(sigMsgLen), msgHash, otsSeed, params.wotsParams, pubSeed, otsAddr);

  sigMsgLen += params.wotsParams.keySize;

  for (
    let sigMsgIndex = sigMsgLen, authIndex = 0;
    sigMsgIndex < sigMsgLen + params.h * params.n && authIndex < params.h * params.n;
    sigMsgIndex++, authIndex++
  ) {
    sigMsg.set([bdsState.auth[authIndex]], sigMsgIndex);
  }

  if (idx < (new Uint32Array([1])[0] << params.h) - 1) {
    bdsRound(hashFunction, bdsState, idx, skSeed, params, pubSeed, otsAddr);
    bdsTreeHashUpdate(hashFunction, bdsState, (params.h - params.k) >>> 1, skSeed, params, pubSeed, otsAddr);
  }

  return { sigMsg, error: null };
}

/**
 * @param {Uint8Array} ePK
 * @returns {Uint8Array}
 */
function getXMSSAddressFromPK(ePK) {
  const desc = newQRLDescriptorFromExtendedPk(ePK);

  if (desc.getAddrFormatType() !== COMMON.SHA256_2X) {
    throw new Error('Address format type not supported');
  }

  const address = new Uint8Array(COMMON.ADDRESS_SIZE);
  const descBytes = desc.getBytes();

  for (
    let addressIndex = 0, descBytesIndex = 0;
    addressIndex < COMMON.DESCRIPTOR_SIZE && descBytesIndex < descBytes.length;
    addressIndex++, descBytesIndex++
  ) {
    address.set([descBytes[descBytesIndex]], addressIndex);
  }

  const hashedKey = new Uint8Array(32);
  shake256(hashedKey, ePK);

  for (
    let addressIndex = COMMON.DESCRIPTOR_SIZE,
      hashedKeyIndex = hashedKey.length - COMMON.ADDRESS_SIZE + COMMON.DESCRIPTOR_SIZE;
    addressIndex < address.length && hashedKeyIndex < hashedKey.length;
    addressIndex++, hashedKeyIndex++
  ) {
    address.set([hashedKey[hashedKeyIndex]], addressIndex);
  }

  return address;
}

class XMSSClass {
  /**
   * @param {Uint32Array[number]} newIndex
   * @returns {void}
   */
  setIndex(newIndex) {
    xmssFastUpdate(this.hashFunction, this.xmssParams, this.sk, this.bdsState, newIndex);
  }

  /** @returns {Uint8Array[number]} */
  getHeight() {
    return this.height;
  }

  /** @returns {Uint8Array} */
  getPKSeed() {
    return this.sk.subarray(OFFSET_PUB_SEED, OFFSET_PUB_SEED + 32);
  }

  /** @returns {Uint8Array} */
  getSeed() {
    return this.seed;
  }

  /** @returns {Uint8Array} */
  getExtendedSeed() {
    const extendedSeed = new Uint8Array(COMMON.EXTENDED_SEED_SIZE);
    const descBytes = this.desc.getBytes();
    const seed = this.getSeed();
    for (
      let extSeedIndex = 0, bytesIndex = 0;
      extSeedIndex < 3 && bytesIndex < descBytes.length;
      extSeedIndex++, bytesIndex++
    ) {
      extendedSeed.set([descBytes[bytesIndex]], extSeedIndex);
    }
    for (
      let extSeedIndex = 3, seedIndex = 0;
      extSeedIndex < extendedSeed.length && seedIndex < seed.length;
      extSeedIndex++, seedIndex++
    ) {
      extendedSeed.set([seed[seedIndex]], extSeedIndex);
    }

    return extendedSeed;
  }

  /** @returns {string} */
  getHexSeed() {
    const eSeed = this.getExtendedSeed();

    return `0x${Array.from(eSeed)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
  }

  /** @returns {string} */
  getMnemonic() {
    return extendedSeedBinToMnemonic(this.getExtendedSeed());
  }

  /** @returns {Uint8Array} */
  getRoot() {
    return this.sk.subarray(OFFSET_ROOT, OFFSET_ROOT + 32);
  }

  /** @returns {Uint8Array} */
  getPK() {
    const desc = this.desc.getBytes();
    const root = this.getRoot();
    const pubSeed = this.getPKSeed();

    const output = new Uint8Array(CONSTANTS.EXTENDED_PK_SIZE);
    let offset = 0;
    for (let i = 0; i < desc.length; i++) {
      output.set([desc[i]], i);
    }
    offset += desc.length;
    for (let i = 0; i < root.length; i++) {
      output.set([root[i]], offset + i);
    }
    offset += root.length;
    for (let i = 0; i < pubSeed.length; i++) {
      output.set([pubSeed[i]], offset + i);
    }

    return output;
  }

  /** @returns {Uint8Array} */
  getSK() {
    return this.sk;
  }

  /** @returns {Uint8Array} */
  getAddress() {
    return getXMSSAddressFromPK(this.getPK());
  }

  /** @returns {Uint32Array[number]} */
  getIndex() {
    return (
      (new Uint32Array([this.sk[0]])[0] << 24) +
      (new Uint32Array([this.sk[1]])[0] << 16) +
      (new Uint32Array([this.sk[2]])[0] << 8) +
      new Uint32Array([this.sk[3]])[0]
    );
  }

  /**
   * @param {Uint8Array} message
   * @returns {SignatureReturnType}
   */
  sign(message) {
    const index = this.getIndex();
    this.setIndex(index);

    return xmssFastSignMessage(this.hashFunction, this.xmssParams, this.sk, this.bdsState, message);
  }

  /**
   * @param {XMSSParams} xmssParams
   * @param {HashFunction} hashFunction
   * @param {Uint8Array[number]} height
   * @param {Uint8Array} sk
   * @param {Uint8Array} seed
   * @param {BDSState} bdsState
   * @param {QRLDescriptor} desc
   */
  constructor(xmssParams, hashFunction, height, sk, seed, bdsState, desc) {
    if (seed.length !== COMMON.SEED_SIZE) {
      throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
    }

    this.xmssParams = xmssParams;
    this.hashFunction = hashFunction;
    this.height = height;
    this.sk = sk;
    this.seed = seed;
    this.bdsState = bdsState;
    this.desc = desc;
  }
}

/**
 * @param {XMSSParams} xmssParams
 * @param {HashFunction} hashFunction
 * @param {Uint8Array[number]} height
 * @param {Uint8Array} sk
 * @param {Uint8Array} seed
 * @param {BDSState} bdsState
 * @param {QRLDescriptor} desc
 * @returns {XMSS}
 */
function newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc) {
  return new XMSSClass(xmssParams, hashFunction, height, sk, seed, bdsState, desc);
}

/**
 * @param {QRLDescriptor} desc
 * @param {Uint8Array} seed
 * @returns {XMSS}
 */
function initializeTree(desc, seed) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }

  const [height] = new Uint32Array([desc.getHeight()]);
  const hashFunction = desc.getHashFunction();
  const sk = new Uint8Array(132);
  const pk = new Uint8Array(64);

  const k = WOTS_PARAM.K;
  const w = WOTS_PARAM.W;
  const n = WOTS_PARAM.N;

  if (k >= height || (height - k) % 2 === 1) {
    throw new Error('For BDS traversal, H - K must be even, with H > K >= 2!');
  }

  const xmssParams = newXMSSParams(n, height, w, k);
  const bdsState = newBDSState(height, n, k);
  XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed);

  return newXMSS(xmssParams, hashFunction, height, sk, seed, bdsState, desc);
}

/**
 * @param {Uint8Array} seed
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @param {AddrFormatType} addrFormatType
 * @returns {XMSS}
 */
function newXMSSFromSeed(seed, height, hashFunction, addrFormatType) {
  if (seed.length !== COMMON.SEED_SIZE) {
    throw new Error(`seed should be an array of size ${COMMON.SEED_SIZE}`);
  }

  const signatureType = COMMON.XMSS_SIG;
  if (height > CONSTANTS.MAX_HEIGHT) {
    throw new Error('Height should be <= 254');
  }
  const desc = newQRLDescriptor(height, hashFunction, signatureType, addrFormatType);

  return initializeTree(desc, seed);
}

/**
 * @param {Uint8Array} extendedSeed
 * @returns {XMSS}
 */
function newXMSSFromExtendedSeed(extendedSeed) {
  if (extendedSeed.length !== COMMON.EXTENDED_SEED_SIZE) {
    throw new Error(`extendedSeed should be an array of size ${COMMON.EXTENDED_SEED_SIZE}`);
  }

  const desc = newQRLDescriptorFromExtendedSeed(extendedSeed);
  const seed = new Uint8Array(COMMON.SEED_SIZE);
  seed.set(extendedSeed.subarray(COMMON.DESCRIPTOR_SIZE));

  return initializeTree(desc, seed);
}

/**
 * @param {Uint8Array[number]} height
 * @param {HashFunction} hashFunction
 * @returns {XMSS}
 */
function newXMSSFromHeight(height, hashFunction) {
  const seed = randomBytes(COMMON.SEED_SIZE);

  return newXMSSFromSeed(seed, height, hashFunction, COMMON.SHA256_2X);
}

export { COMMON, CONSTANTS, ENDIAN, HASH_FUNCTION, OFFSET_IDX, OFFSET_PUB_SEED, OFFSET_ROOT, OFFSET_SK_PRF, OFFSET_SK_SEED, WOTS_PARAM, XMSSFastGenKeyPair, addrToByte, bdsRound, bdsTreeHashUpdate, binToMnemonic, calcBaseW, calculateSignatureBaseSize, coreHash, expandSeed, extendedSeedBinToMnemonic, genChain, genLeafWOTS, getSeed, getSignatureSize, getXMSSAddressFromPK, hMsg, hashF, hashH, initializeTree, lTree, mnemonicToBin, mnemonicToExtendedSeedBin, mnemonicToSeedBin, newBDSState, newQRLDescriptor, newQRLDescriptorFromBytes, newQRLDescriptorFromExtendedPk, newQRLDescriptorFromExtendedSeed, newTreeHashInst, newWOTSParams, newXMSS, newXMSSFromExtendedSeed, newXMSSFromHeight, newXMSSFromSeed, newXMSSParams, prf, seedBinToMnemonic, setChainAddr, setHashAddr, setKeyAndMask, setLTreeAddr, setOTSAddr, setTreeHeight, setTreeIndex, setType, sha256, shake128, shake256, toByteLittleEndian, treeHashMinHeightOnStack, treeHashSetup, treeHashUpdate, wOTSPKGen, wotsSign, xmssFastSignMessage, xmssFastUpdate };
