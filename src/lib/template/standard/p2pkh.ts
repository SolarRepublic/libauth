import type { AuthenticationTemplate } from '../template-types';

/**
 * A standard single-factor authentication template which uses
 * Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use
 * on the network.
 *
 * This P2PKH template uses BCH Schnorr signatures, reducing the size of
 * transactions.
 *
 * Note, this authentication template uses only a single `Key`. For HD key
 * support, see `authenticationTemplateP2pkhHd`.
 */
export const authenticationTemplateP2pkhNonHd: AuthenticationTemplate = {
  $schema: 'https://bitauth.com/schemas/authentication-template-v0.schema.json',
  description:
    'A standard single-factor authentication template which uses Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use on the network.\n\nThis P2PKH template uses BCH Schnorr signatures, reducing the size of transactions.',
  entities: {
    owner: {
      description: 'The individual who can spend from this wallet.',
      name: 'Owner',
      scripts: ['lock', 'unlock'],
      variables: {
        key: {
          description: 'The private key which controls this wallet.',
          name: 'Key',
          type: 'Key',
        },
      },
    },
  },
  name: 'Single Signature (P2PKH)',
  scripts: {
    lock: {
      lockingType: 'standard',
      name: 'P2PKH Lock',
      script:
        'OP_DUP\nOP_HASH160 <$(<key.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG',
    },
    unlock: {
      name: 'Unlock',
      script: '<key.schnorr_signature.all_outputs>\n<key.public_key>',
      unlocks: 'lock',
    },
  },
  supported: ['BCH_2019_05', 'BCH_2019_11', 'BCH_2020_05'],
  version: 0,
};

/**
 * A standard single-factor authentication template which uses
 * Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use
 * on the network.
 *
 * This P2PKH template uses BCH Schnorr signatures, reducing the size of
 * transactions.
 *
 * Because the template uses a Hierarchical Deterministic (HD) key, it also
 * supports an "Observer (Watch-Only)" entity.
 */
export const authenticationTemplateP2pkh: AuthenticationTemplate = {
  $schema: 'https://bitauth.com/schemas/authentication-template-v0.schema.json',
  description:
    'A standard single-factor authentication template which uses Pay-to-Public-Key-Hash (P2PKH), the most common authentication scheme in use on the network.\n\nThis P2PKH template uses BCH Schnorr signatures, reducing the size of transactions. Because the template uses a Hierarchical Deterministic (HD) key, it also supports an "Observer (Watch-Only)" entity.',
  entities: {
    observer: {
      description:
        'An entity which can generate addresses but cannot spend funds from this wallet.',
      name: 'Observer (Watch-Only)',
      scripts: ['lock'],
    },
    owner: {
      description: 'The individual who can spend from this wallet.',
      name: 'Owner',
      scripts: ['lock', 'unlock'],
      variables: {
        key: {
          description: 'The private key which controls this wallet.',
          name: 'Key',
          type: 'HdKey',
        },
      },
    },
  },
  name: 'Single Signature (P2PKH)',
  scripts: {
    lock: {
      lockingType: 'standard',
      name: 'P2PKH Lock',
      script:
        'OP_DUP\nOP_HASH160 <$(<key.public_key> OP_HASH160\n)> OP_EQUALVERIFY\nOP_CHECKSIG',
    },
    unlock: {
      name: 'Unlock',
      script: '<key.schnorr_signature.all_outputs>\n<key.public_key>',
      unlocks: 'lock',
    },
  },
  supported: ['BCH_2019_05', 'BCH_2019_11', 'BCH_2020_05'],
  version: 0,
};
