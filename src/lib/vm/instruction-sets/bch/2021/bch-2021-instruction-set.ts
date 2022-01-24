import type { Ripemd160, Secp256k1, Sha1, Sha256 } from '../../../../lib';
import type { InstructionSet } from '../../../vm';
import type {
  AuthenticationProgramBCH,
  AuthenticationProgramStateBCH,
  ResolvedTransactionBCH,
} from '../../instruction-sets.js';
import {
  conditionallyEvaluate,
  createInstructionSetBCH2022,
  mapOverOperations,
  OpcodesBCH,
} from '../../instruction-sets.js';

import {
  op0NotEqual4Byte,
  op1Add4Byte,
  op1Sub4Byte,
  opAbs4Byte,
  opAdd4Byte,
  opBin2Num4Byte,
  opBoolAnd4Byte,
  opBoolOr4Byte,
  opDiv4Byte,
  opGreaterThan4Byte,
  opGreaterThanOrEqual4Byte,
  opLessThan4Byte,
  opLessThanOrEqual4Byte,
  opMax4Byte,
  opMin4Byte,
  opMod4Byte,
  opNegate4Byte,
  opNot4Byte,
  opNum2Bin4Byte,
  opNumEqual4Byte,
  opNumEqualVerify4Byte,
  opNumNotEqual4Byte,
  opPick4Byte,
  opRoll4Byte,
  opSplit4Byte,
  opSub4Byte,
  opWithin4Byte,
} from './bch-2021-vm-number-operations.js';

/**
 * create an instance of the BCH 2021 virtual machine instruction set.
 *
 * @param standard - If `true`, the additional `isStandard` validations will be
 * enabled. Transactions which fail these rules are often called "non-standard"
 * and can technically be included by miners in valid blocks, but most network
 * nodes will refuse to relay them. (Default: `true`)
 * @param sha1 - a Sha1 implementation
 * @param sha256 - a Sha256 implementation
 * @param ripemd160 - a Ripemd160 implementation
 * @param secp256k1 - a Secp256k1 implementation
 */
export const createInstructionSetBCH2021 = ({
  ripemd160,
  secp256k1,
  sha1,
  sha256,
  standard = true,
}: {
  ripemd160: { hash: Ripemd160['hash'] };
  secp256k1: {
    verifySignatureSchnorr: Secp256k1['verifySignatureSchnorr'];
    verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
  };
  sha1: { hash: Sha1['hash'] };
  sha256: { hash: Sha256['hash'] };
  standard?: boolean;
}): InstructionSet<
  ResolvedTransactionBCH,
  AuthenticationProgramBCH,
  AuthenticationProgramStateBCH
> => {
  const instructionSet = createInstructionSetBCH2022({
    ripemd160,
    secp256k1,
    sha1,
    sha256,
    standard,
  });

  return {
    ...instructionSet,
    operations: {
      ...instructionSet.operations,
      ...mapOverOperations<AuthenticationProgramStateBCH>(
        [conditionallyEvaluate],
        {
          [OpcodesBCH.OP_PICK]: opPick4Byte,
          [OpcodesBCH.OP_ROLL]: opRoll4Byte,
          [OpcodesBCH.OP_SPLIT]: opSplit4Byte,
          [OpcodesBCH.OP_NUM2BIN]: opNum2Bin4Byte,
          [OpcodesBCH.OP_BIN2NUM]: opBin2Num4Byte,
          [OpcodesBCH.OP_1ADD]: op1Add4Byte,
          [OpcodesBCH.OP_1SUB]: op1Sub4Byte,
          [OpcodesBCH.OP_NEGATE]: opNegate4Byte,
          [OpcodesBCH.OP_ABS]: opAbs4Byte,
          [OpcodesBCH.OP_NOT]: opNot4Byte,
          [OpcodesBCH.OP_0NOTEQUAL]: op0NotEqual4Byte,
          [OpcodesBCH.OP_ADD]: opAdd4Byte,
          [OpcodesBCH.OP_SUB]: opSub4Byte,
          [OpcodesBCH.OP_DIV]: opDiv4Byte,
          [OpcodesBCH.OP_MOD]: opMod4Byte,
          [OpcodesBCH.OP_BOOLAND]: opBoolAnd4Byte,
          [OpcodesBCH.OP_BOOLOR]: opBoolOr4Byte,
          [OpcodesBCH.OP_NUMEQUAL]: opNumEqual4Byte,
          [OpcodesBCH.OP_NUMEQUALVERIFY]: opNumEqualVerify4Byte,
          [OpcodesBCH.OP_NUMNOTEQUAL]: opNumNotEqual4Byte,
          [OpcodesBCH.OP_LESSTHAN]: opLessThan4Byte,
          [OpcodesBCH.OP_GREATERTHAN]: opGreaterThan4Byte,
          [OpcodesBCH.OP_LESSTHANOREQUAL]: opLessThanOrEqual4Byte,
          [OpcodesBCH.OP_GREATERTHANOREQUAL]: opGreaterThanOrEqual4Byte,
          [OpcodesBCH.OP_MIN]: opMin4Byte,
          [OpcodesBCH.OP_MAX]: opMax4Byte,
          [OpcodesBCH.OP_WITHIN]: opWithin4Byte,
        }
      ),
    },
  };
};
