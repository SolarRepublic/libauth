/* eslint-disable camelcase, @typescript-eslint/naming-convention */
import type { AuthenticationTemplate } from '../../template/template-types';

export const sigOfSig: AuthenticationTemplate = {
  ...{
    name: 'Sig-of-Sig Vault (2-of-2)',
  },
  description:
    'An unusual example of a template which must be signed in a specific order: Second Signer may only sign after First Signer.',
  entities: {
    signer_1: {
      name: 'First Signer',
      variables: {
        first: {
          type: 'HdKey',
        },
      },
    },
    signer_2: {
      name: 'Second Signer',
      variables: {
        second: {
          type: 'HdKey',
        },
      },
    },
  },
  scripts: {
    first_signature: {
      script: 'first.signature.all_outputs',
    },
    lock: {
      lockingType: 'p2sh',
      name: 'Sig-of-Sig Vault',
      script:
        'OP_2 OP_PICK <second.public_key> OP_CHECKDATASIGVERIFY OP_DUP OP_HASH160 <$(<first.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG',
    },
    spend: {
      script:
        '<first.signature.all_outputs> <first.public_key> <second.data_signature.first_signature>',
      unlocks: 'lock',
    },
  },
  supported: ['BCH_2019_11'],
  version: 0,
};
