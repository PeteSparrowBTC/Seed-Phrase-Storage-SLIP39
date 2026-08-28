// Independent expectations for the computed multisig descriptor and first receive
// address, for MultisigWalletTests to be pinned against.
//
// WHY THIS EXISTS. Slip39Demo.Core derives the descriptor with its own BIP-32, its own
// base58, its own bech32 and its own witness-script assembly. A test that pinned those
// against values the same code produced would only prove the code is deterministic. So
// the expectations come from somewhere else: @scure/bip32 for derivation and xpub
// serialisation, @scure/btc-signer for the multisig script and the address, neither of
// which shares a line with this repository. This is the same argument that put the
// official age binary on the encryption path and GnuPG on the outer lock: the check has
// to come from software we did not write.
//
// The descriptor checksum is the one part with no second implementation to hand, so it
// is transcribed here from the Python in BIP-380 and pinned to the BIP's own published
// vector, raw(deadbeef)#89f8spxm, which the first line of output confirms.
//
// The seed words are published BIP-39 test vectors, so the mnemonic-to-seed half of the
// chain is already pinned by the vector file Slip39Demo.Tests runs.
//
// Run:  npm install && node crosscheck.mjs
// Every line must say OK. A FAIL means this stack and Slip39Demo.Core disagree, and the
// C# side is not the automatic winner.

import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';

// --- BIP-380 descriptor checksum, transcribed from the reference Python in the BIP ---

const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

const polymod = symbols => {
  let chk = 1n;
  for (const value of symbols) {
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= GENERATOR[i];
  }
  return chk;
};

const expand = s => {
  const groups = [];
  const symbols = [];
  for (const c of s) {
    const v = INPUT_CHARSET.indexOf(c);
    if (v < 0) throw new Error(`character outside the BIP-380 set: ${c}`);
    symbols.push(v & 31);
    groups.push(v >> 5);
    if (groups.length === 3) {
      symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
      groups.length = 0;
    }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  else if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
  return symbols;
};

const withChecksum = descriptor => {
  const checksum = polymod([...expand(descriptor), 0, 0, 0, 0, 0, 0, 0, 0]) ^ 1n;
  let out = '';
  for (let i = 0; i < 8; i++) out += CHECKSUM_CHARSET[Number((checksum >> (5n * BigInt(7 - i))) & 31n)];
  return `${descriptor}#${out}`;
};

// --- The wallet ---

// Published BIP-39 English test vectors.
const SEEDS = {
  a: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  b: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
  c: 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
};

const BIP48 = "m/48'/0'/0'/2'";

const accountKey = ({ seed, passphrase = '', path = BIP48 }) => {
  const master = HDKey.fromMasterSeed(mnemonicToSeedSync(seed, passphrase));
  const account = master.derive(path);
  return {
    fingerprint: master.fingerprint.toString(16).padStart(8, '0'),
    path: path.replace(/^m\//, '').replaceAll("'", 'h'),
    xpub: account.publicExtendedKey,
    // Receive branch 0, first index 0.
    firstReceiveKey: account.deriveChild(0).deriveChild(0).publicKey,
  };
};

const describe = (cosigners, signaturesRequired) => {
  const keys = cosigners.map(accountKey);

  // BIP-67: sortedmulti orders the derived compressed public keys, not the xpubs.
  const sorted = [...keys].sort((left, right) =>
    hex.encode(left.firstReceiveKey).localeCompare(hex.encode(right.firstReceiveKey)));

  const address = btc.p2wsh(btc.p2ms(signaturesRequired, sorted.map(key => key.firstReceiveKey))).address;

  const expressions = keys
    .map(key => `[${key.fingerprint}/${key.path}]${key.xpub}/0/*`)
    .sort();

  return {
    descriptor: withChecksum(`wsh(sortedmulti(${signaturesRequired},${expressions.join(',')}))`),
    address,
  };
};

// --- What MultisigWalletTests pins, checked against what this stack computes ---

let failures = 0;

const check = (what, actual, expected) => {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${what}`);
  if (!ok) {
    console.log(`       this stack: ${actual}`);
    console.log(`       C# pins:    ${expected}`);
  }
};

check('BIP-380 published checksum vector', withChecksum('raw(deadbeef)'), 'raw(deadbeef)#89f8spxm');

const twoOfTwo = describe([{ seed: SEEDS.a }, { seed: SEEDS.b }], 2);
check('2-of-2 descriptor', twoOfTwo.descriptor,
  'wsh(sortedmulti(2,'
  + '[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/0/*,'
  + '[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/0/*'
  + '))#68nqsuv4');
check('2-of-2 first address', twoOfTwo.address,
  'bc1qsks3qr92vdnr80q6y9vv6h4qwlzza9w8ts2pjp74wjj6ahvud5dsc3vhxe');

const otherOrder = describe([{ seed: SEEDS.b }, { seed: SEEDS.a }], 2);
check('2-of-2 is order independent', otherOrder.address, twoOfTwo.address);

const accountOne = describe([{ seed: SEEDS.a }, { seed: SEEDS.b, path: "m/48'/0'/1'/2'" }], 2);
check("account 1h changes the address", accountOne.address,
  'bc1qape6xeexx335klk2prt0pcsztyftxe688uwcrzctq4lwydascavsh6duer');

const twoOfThree = describe([{ seed: SEEDS.a }, { seed: SEEDS.b }, { seed: SEEDS.c }], 2);
check('2-of-3 first address', twoOfThree.address,
  'bc1qm43n7nnev58aj3nrznz2xscgv98t7gxycq5pmp20a5vzfp5t0q2s7r6twa');
check('2-of-3 descriptor checksum', twoOfThree.descriptor.slice(-9), '#kp9wmyws');

const passphrased = describe([{ seed: SEEDS.a, passphrase: 'TREZOR' }, { seed: SEEDS.b }], 2);
check('a passphrase reaches the derivation', passphrased.address,
  'bc1qn2d8rveja5hg62ppv8zg65zsm723ajsxpe22y8gwfkl96r8rsvmsydwyef');

console.log(failures === 0
  ? '\nAll expectations agree with this independent stack.'
  : `\n${failures} disagreement(s). Do not assume the C# side is right.`);

process.exit(failures === 0 ? 0 : 1);
