import {
  instantiateRipemd160,
  instantiateSecp256k1,
  instantiateSha1,
  instantiateSha256,
} from '../../../../lib.js';
import { createAuthenticationVirtualMachine } from '../../../virtual-machine.js';

import { createInstructionSetBCH2021 } from './bch-2021-instruction-set.js';

/**
 * Initialize a virtual machine using the BCH instruction set.
 *
 * @param standard - If `true`, the additional `isStandard` validations will be
 * enabled. Transactions which fail these rules are often called "non-standard"
 * and can technically be included by miners in valid blocks, but most network
 * nodes will refuse to relay them. (Default: `true`)
 */
export const instantiateVirtualMachineBCH2021 = async (standard = true) => {
  const [sha1, sha256, ripemd160, secp256k1] = await Promise.all([
    instantiateSha1(),
    instantiateSha256(),
    instantiateRipemd160(),
    instantiateSecp256k1(),
  ]);
  return createAuthenticationVirtualMachine(
    createInstructionSetBCH2021({
      ripemd160,
      secp256k1,
      sha1,
      sha256,
      standard,
    })
  );
};
