import {
  ripemd160 as internalRipemd160,
  secp256k1 as internalSecp256k1,
  sha1 as internalSha1,
  sha256 as internalSha256,
} from '../../../../crypto/default-crypto-instances.js';
import type { Ripemd160, Secp256k1, Sha1, Sha256 } from '../../../../lib';
import type { InstructionSet } from '../../../vm';
import type {
  AuthenticationProgramBCH,
  AuthenticationProgramStateBCH,
  ResolvedTransactionBCH,
} from '../../instruction-sets.js';
import {
  applyError,
  AuthenticationErrorCommon,
  authenticationInstructionsAreMalformed,
  cloneAuthenticationProgramStateBCH,
  cloneStack,
  conditionallyEvaluate,
  ConsensusBCH2022,
  createAuthenticationProgramStateCommon,
  decodeAuthenticationInstructions,
  disabledOperation,
  incrementOperationCount,
  isArbitraryDataOutput,
  isPayToScriptHash20,
  isPushOnly,
  isStandardOutputBytecode,
  isWitnessProgram,
  mapOverOperations,
  op0NotEqual,
  op1Add,
  op1Sub,
  op2Drop,
  op2Dup,
  op2Over,
  op2Rot,
  op2Swap,
  op3Dup,
  opAbs,
  opAdd,
  opAnd,
  opBin2Num,
  opBoolAnd,
  opBoolOr,
  opCat,
  opCheckDataSig,
  opCheckDataSigVerify,
  opCheckLockTimeVerify,
  opCheckMultiSig,
  opCheckMultiSigVerify,
  opCheckSequenceVerify,
  opCheckSig,
  opCheckSigVerify,
  OpcodesBCH,
  opCodeSeparator,
  opDepth,
  opDiv,
  opDrop,
  opDup,
  opElse,
  opEndIf,
  opEqual,
  opEqualVerify,
  opFromAltStack,
  opGreaterThan,
  opGreaterThanOrEqual,
  opHash160,
  opHash256,
  opIf,
  opIfDup,
  opLessThan,
  opLessThanOrEqual,
  opMax,
  opMin,
  opMod,
  opNegate,
  opNip,
  opNop,
  opNopDisallowed,
  opNot,
  opNotIf,
  opNum2Bin,
  opNumEqual,
  opNumEqualVerify,
  opNumNotEqual,
  opOr,
  opOver,
  opPick,
  opReturn,
  opReverseBytes,
  opRipemd160,
  opRoll,
  opRot,
  opSha1,
  opSha256,
  opSize,
  opSplit,
  opSub,
  opSwap,
  opToAltStack,
  opTuck,
  opVerify,
  opWithin,
  opXor,
  pushNumberOperation,
  pushOperation,
  reservedOperation,
  stackItemIsTruthy,
  undefinedOperation,
} from '../../instruction-sets.js';

import { encodeTransactionBCH } from './bch-2022-types.js';

/**
 * create an instance of the BCH 2022 virtual machine instruction set.
 *
 * @param standard - If `true`, the additional `isStandard` validations will be
 * enabled. Transactions that fail these rules are often called "non-standard"
 * and can technically be included by miners in valid blocks, but most network
 * nodes will refuse to relay them. (Default: `true`)
 */
export const createInstructionSetBCH2022 = (
  standard = true,
  {
    ripemd160,
    secp256k1,
    sha1,
    sha256,
  }: {
    /**
     * a Ripemd160 implementation
     */
    ripemd160: { hash: Ripemd160['hash'] };
    /**
     * a Secp256k1 implementation
     */
    secp256k1: {
      verifySignatureSchnorr: Secp256k1['verifySignatureSchnorr'];
      verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
    };
    /**
     * a Sha1 implementation
     */
    sha1: { hash: Sha1['hash'] };
    /**
     * a Sha256 implementation
     */
    sha256: { hash: Sha256['hash'] };
  } = {
    ripemd160: internalRipemd160,
    secp256k1: internalSecp256k1,
    sha1: internalSha1,
    sha256: internalSha256,
  }
): InstructionSet<
  ResolvedTransactionBCH,
  AuthenticationProgramBCH,
  AuthenticationProgramStateBCH
> => {
  const push = pushOperation<AuthenticationProgramStateBCH>();
  return {
    clone: cloneAuthenticationProgramStateBCH,
    continue: (state) =>
      state.error === undefined && state.ip < state.instructions.length,
    // eslint-disable-next-line complexity
    evaluate: (program, stateEvaluate) => {
      const { unlockingBytecode } =
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        program.transaction.inputs[program.inputIndex]!;
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const { lockingBytecode } = program.sourceOutputs[program.inputIndex]!;
      const unlockingInstructions =
        decodeAuthenticationInstructions(unlockingBytecode);
      const lockingInstructions =
        decodeAuthenticationInstructions(lockingBytecode);
      const initialState = createAuthenticationProgramStateCommon({
        instructions: unlockingInstructions,
        program,
        stack: [],
      });

      if (unlockingBytecode.length > ConsensusBCH2022.maximumBytecodeLength) {
        return applyError(
          `The provided unlocking bytecode (${unlockingBytecode.length} bytes) exceeds the maximum bytecode length (${ConsensusBCH2022.maximumBytecodeLength} bytes).`,
          initialState
        );
      }
      if (authenticationInstructionsAreMalformed(unlockingInstructions)) {
        return applyError(
          AuthenticationErrorCommon.malformedUnlockingBytecode,
          initialState
        );
      }
      if (lockingBytecode.length > ConsensusBCH2022.maximumBytecodeLength) {
        return applyError(
          AuthenticationErrorCommon.exceededMaximumBytecodeLengthLocking,
          initialState
        );
      }
      if (authenticationInstructionsAreMalformed(lockingInstructions)) {
        return applyError(
          AuthenticationErrorCommon.malformedLockingBytecode,
          initialState
        );
      }
      if (standard && !isPushOnly(unlockingBytecode)) {
        return applyError(
          AuthenticationErrorCommon.requiresPushOnly,
          initialState
        );
      }
      const unlockingResult = stateEvaluate(initialState);
      if (unlockingResult.error !== undefined) {
        return unlockingResult;
      }
      const lockingResult = stateEvaluate(
        createAuthenticationProgramStateCommon({
          instructions: lockingInstructions,
          program,
          stack: unlockingResult.stack,
        })
      );
      if (!isPayToScriptHash20(lockingBytecode)) {
        return lockingResult;
      }

      const p2shStack = cloneStack(unlockingResult.stack);
      // eslint-disable-next-line functional/immutable-data
      const p2shScript = p2shStack.pop() ?? Uint8Array.of();

      if (p2shStack.length === 0 && isWitnessProgram(p2shScript)) {
        return lockingResult;
      }

      const p2shInstructions = decodeAuthenticationInstructions(p2shScript);
      return authenticationInstructionsAreMalformed(p2shInstructions)
        ? {
            ...lockingResult,
            error: AuthenticationErrorCommon.malformedP2shBytecode,
          }
        : stateEvaluate(
            createAuthenticationProgramStateCommon({
              instructions: p2shInstructions,
              program,
              stack: p2shStack,
            })
          );
    },
    every: (state) =>
      // TODO: implement sigchecks https://gitlab.com/bitcoin-cash-node/bchn-sw/bitcoincash-upgrade-specifications/-/blob/master/spec/2020-05-15-sigchecks.md
      state.stack.length + state.alternateStack.length >
      ConsensusBCH2022.maximumStackDepth
        ? applyError(AuthenticationErrorCommon.exceededMaximumStackDepth, state)
        : state.operationCount > ConsensusBCH2022.maximumOperationCount
        ? applyError(
            AuthenticationErrorCommon.exceededMaximumOperationCount,
            state
          )
        : state,
    operations: {
      [OpcodesBCH.OP_0]: push,
      [OpcodesBCH.OP_PUSHBYTES_1]: push,
      [OpcodesBCH.OP_PUSHBYTES_2]: push,
      [OpcodesBCH.OP_PUSHBYTES_3]: push,
      [OpcodesBCH.OP_PUSHBYTES_4]: push,
      [OpcodesBCH.OP_PUSHBYTES_5]: push,
      [OpcodesBCH.OP_PUSHBYTES_6]: push,
      [OpcodesBCH.OP_PUSHBYTES_7]: push,
      [OpcodesBCH.OP_PUSHBYTES_8]: push,
      [OpcodesBCH.OP_PUSHBYTES_9]: push,
      [OpcodesBCH.OP_PUSHBYTES_10]: push,
      [OpcodesBCH.OP_PUSHBYTES_11]: push,
      [OpcodesBCH.OP_PUSHBYTES_12]: push,
      [OpcodesBCH.OP_PUSHBYTES_13]: push,
      [OpcodesBCH.OP_PUSHBYTES_14]: push,
      [OpcodesBCH.OP_PUSHBYTES_15]: push,
      [OpcodesBCH.OP_PUSHBYTES_16]: push,
      [OpcodesBCH.OP_PUSHBYTES_17]: push,
      [OpcodesBCH.OP_PUSHBYTES_18]: push,
      [OpcodesBCH.OP_PUSHBYTES_19]: push,
      [OpcodesBCH.OP_PUSHBYTES_20]: push,
      [OpcodesBCH.OP_PUSHBYTES_21]: push,
      [OpcodesBCH.OP_PUSHBYTES_22]: push,
      [OpcodesBCH.OP_PUSHBYTES_23]: push,
      [OpcodesBCH.OP_PUSHBYTES_24]: push,
      [OpcodesBCH.OP_PUSHBYTES_25]: push,
      [OpcodesBCH.OP_PUSHBYTES_26]: push,
      [OpcodesBCH.OP_PUSHBYTES_27]: push,
      [OpcodesBCH.OP_PUSHBYTES_28]: push,
      [OpcodesBCH.OP_PUSHBYTES_29]: push,
      [OpcodesBCH.OP_PUSHBYTES_30]: push,
      [OpcodesBCH.OP_PUSHBYTES_31]: push,
      [OpcodesBCH.OP_PUSHBYTES_32]: push,
      [OpcodesBCH.OP_PUSHBYTES_33]: push,
      [OpcodesBCH.OP_PUSHBYTES_34]: push,
      [OpcodesBCH.OP_PUSHBYTES_35]: push,
      [OpcodesBCH.OP_PUSHBYTES_36]: push,
      [OpcodesBCH.OP_PUSHBYTES_37]: push,
      [OpcodesBCH.OP_PUSHBYTES_38]: push,
      [OpcodesBCH.OP_PUSHBYTES_39]: push,
      [OpcodesBCH.OP_PUSHBYTES_40]: push,
      [OpcodesBCH.OP_PUSHBYTES_41]: push,
      [OpcodesBCH.OP_PUSHBYTES_42]: push,
      [OpcodesBCH.OP_PUSHBYTES_43]: push,
      [OpcodesBCH.OP_PUSHBYTES_44]: push,
      [OpcodesBCH.OP_PUSHBYTES_45]: push,
      [OpcodesBCH.OP_PUSHBYTES_46]: push,
      [OpcodesBCH.OP_PUSHBYTES_47]: push,
      [OpcodesBCH.OP_PUSHBYTES_48]: push,
      [OpcodesBCH.OP_PUSHBYTES_49]: push,
      [OpcodesBCH.OP_PUSHBYTES_50]: push,
      [OpcodesBCH.OP_PUSHBYTES_51]: push,
      [OpcodesBCH.OP_PUSHBYTES_52]: push,
      [OpcodesBCH.OP_PUSHBYTES_53]: push,
      [OpcodesBCH.OP_PUSHBYTES_54]: push,
      [OpcodesBCH.OP_PUSHBYTES_55]: push,
      [OpcodesBCH.OP_PUSHBYTES_56]: push,
      [OpcodesBCH.OP_PUSHBYTES_57]: push,
      [OpcodesBCH.OP_PUSHBYTES_58]: push,
      [OpcodesBCH.OP_PUSHBYTES_59]: push,
      [OpcodesBCH.OP_PUSHBYTES_60]: push,
      [OpcodesBCH.OP_PUSHBYTES_61]: push,
      [OpcodesBCH.OP_PUSHBYTES_62]: push,
      [OpcodesBCH.OP_PUSHBYTES_63]: push,
      [OpcodesBCH.OP_PUSHBYTES_64]: push,
      [OpcodesBCH.OP_PUSHBYTES_65]: push,
      [OpcodesBCH.OP_PUSHBYTES_66]: push,
      [OpcodesBCH.OP_PUSHBYTES_67]: push,
      [OpcodesBCH.OP_PUSHBYTES_68]: push,
      [OpcodesBCH.OP_PUSHBYTES_69]: push,
      [OpcodesBCH.OP_PUSHBYTES_70]: push,
      [OpcodesBCH.OP_PUSHBYTES_71]: push,
      [OpcodesBCH.OP_PUSHBYTES_72]: push,
      [OpcodesBCH.OP_PUSHBYTES_73]: push,
      [OpcodesBCH.OP_PUSHBYTES_74]: push,
      [OpcodesBCH.OP_PUSHBYTES_75]: push,
      [OpcodesBCH.OP_PUSHDATA_1]: push,
      [OpcodesBCH.OP_PUSHDATA_2]: push,
      [OpcodesBCH.OP_PUSHDATA_4]: push,
      [OpcodesBCH.OP_1NEGATE]: conditionallyEvaluate(pushNumberOperation(-1)),
      [OpcodesBCH.OP_RESERVED]: conditionallyEvaluate(reservedOperation),
      [OpcodesBCH.OP_1]: conditionallyEvaluate(pushNumberOperation(1)),
      /* eslint-disable @typescript-eslint/no-magic-numbers */
      [OpcodesBCH.OP_2]: conditionallyEvaluate(pushNumberOperation(2)),
      [OpcodesBCH.OP_3]: conditionallyEvaluate(pushNumberOperation(3)),
      [OpcodesBCH.OP_4]: conditionallyEvaluate(pushNumberOperation(4)),
      [OpcodesBCH.OP_5]: conditionallyEvaluate(pushNumberOperation(5)),
      [OpcodesBCH.OP_6]: conditionallyEvaluate(pushNumberOperation(6)),
      [OpcodesBCH.OP_7]: conditionallyEvaluate(pushNumberOperation(7)),
      [OpcodesBCH.OP_8]: conditionallyEvaluate(pushNumberOperation(8)),
      [OpcodesBCH.OP_9]: conditionallyEvaluate(pushNumberOperation(9)),
      [OpcodesBCH.OP_10]: conditionallyEvaluate(pushNumberOperation(10)),
      [OpcodesBCH.OP_11]: conditionallyEvaluate(pushNumberOperation(11)),
      [OpcodesBCH.OP_12]: conditionallyEvaluate(pushNumberOperation(12)),
      [OpcodesBCH.OP_13]: conditionallyEvaluate(pushNumberOperation(13)),
      [OpcodesBCH.OP_14]: conditionallyEvaluate(pushNumberOperation(14)),
      [OpcodesBCH.OP_15]: conditionallyEvaluate(pushNumberOperation(15)),
      [OpcodesBCH.OP_16]: conditionallyEvaluate(pushNumberOperation(16)),
      /* eslint-enable @typescript-eslint/no-magic-numbers */
      ...mapOverOperations<AuthenticationProgramStateBCH>(
        [incrementOperationCount],
        {
          [OpcodesBCH.OP_NOP]: conditionallyEvaluate(opNop),
          [OpcodesBCH.OP_VER]: conditionallyEvaluate(reservedOperation),
          [OpcodesBCH.OP_IF]: opIf,
          [OpcodesBCH.OP_NOTIF]: opNotIf,
          [OpcodesBCH.OP_VERIF]: reservedOperation,
          [OpcodesBCH.OP_VERNOTIF]: reservedOperation,
          [OpcodesBCH.OP_ELSE]: opElse,
          [OpcodesBCH.OP_ENDIF]: opEndIf,
          [OpcodesBCH.OP_VERIFY]: conditionallyEvaluate(opVerify),
          [OpcodesBCH.OP_RETURN]: conditionallyEvaluate(opReturn),
          [OpcodesBCH.OP_TOALTSTACK]: conditionallyEvaluate(opToAltStack),
          [OpcodesBCH.OP_FROMALTSTACK]: conditionallyEvaluate(opFromAltStack),
          [OpcodesBCH.OP_2DROP]: conditionallyEvaluate(op2Drop),
          [OpcodesBCH.OP_2DUP]: conditionallyEvaluate(op2Dup),
          [OpcodesBCH.OP_3DUP]: conditionallyEvaluate(op3Dup),
          [OpcodesBCH.OP_2OVER]: conditionallyEvaluate(op2Over),
          [OpcodesBCH.OP_2ROT]: conditionallyEvaluate(op2Rot),
          [OpcodesBCH.OP_2SWAP]: conditionallyEvaluate(op2Swap),
          [OpcodesBCH.OP_IFDUP]: conditionallyEvaluate(opIfDup),
          [OpcodesBCH.OP_DEPTH]: conditionallyEvaluate(opDepth),
          [OpcodesBCH.OP_DROP]: conditionallyEvaluate(opDrop),
          [OpcodesBCH.OP_DUP]: conditionallyEvaluate(opDup),
          [OpcodesBCH.OP_NIP]: conditionallyEvaluate(opNip),
          [OpcodesBCH.OP_OVER]: conditionallyEvaluate(opOver),
          [OpcodesBCH.OP_PICK]: conditionallyEvaluate(opPick),
          [OpcodesBCH.OP_ROLL]: conditionallyEvaluate(opRoll),
          [OpcodesBCH.OP_ROT]: conditionallyEvaluate(opRot),
          [OpcodesBCH.OP_SWAP]: conditionallyEvaluate(opSwap),
          [OpcodesBCH.OP_TUCK]: conditionallyEvaluate(opTuck),
          [OpcodesBCH.OP_CAT]: conditionallyEvaluate(opCat),
          [OpcodesBCH.OP_SPLIT]: conditionallyEvaluate(opSplit),
          [OpcodesBCH.OP_NUM2BIN]: conditionallyEvaluate(opNum2Bin),
          [OpcodesBCH.OP_BIN2NUM]: conditionallyEvaluate(opBin2Num),
          [OpcodesBCH.OP_SIZE]: conditionallyEvaluate(opSize),
          [OpcodesBCH.OP_INVERT]: disabledOperation,
          [OpcodesBCH.OP_AND]: conditionallyEvaluate(opAnd),
          [OpcodesBCH.OP_OR]: conditionallyEvaluate(opOr),
          [OpcodesBCH.OP_XOR]: conditionallyEvaluate(opXor),
          [OpcodesBCH.OP_EQUAL]: conditionallyEvaluate(opEqual),
          [OpcodesBCH.OP_EQUALVERIFY]: conditionallyEvaluate(opEqualVerify),
          [OpcodesBCH.OP_RESERVED1]: conditionallyEvaluate(reservedOperation),
          [OpcodesBCH.OP_RESERVED2]: conditionallyEvaluate(reservedOperation),
          [OpcodesBCH.OP_1ADD]: conditionallyEvaluate(op1Add),
          [OpcodesBCH.OP_1SUB]: conditionallyEvaluate(op1Sub),
          [OpcodesBCH.OP_2MUL]: disabledOperation,
          [OpcodesBCH.OP_2DIV]: disabledOperation,
          [OpcodesBCH.OP_NEGATE]: conditionallyEvaluate(opNegate),
          [OpcodesBCH.OP_ABS]: conditionallyEvaluate(opAbs),
          [OpcodesBCH.OP_NOT]: conditionallyEvaluate(opNot),
          [OpcodesBCH.OP_0NOTEQUAL]: conditionallyEvaluate(op0NotEqual),
          [OpcodesBCH.OP_ADD]: conditionallyEvaluate(opAdd),
          [OpcodesBCH.OP_SUB]: conditionallyEvaluate(opSub),
          [OpcodesBCH.OP_MUL]: disabledOperation,
          [OpcodesBCH.OP_DIV]: conditionallyEvaluate(opDiv),
          [OpcodesBCH.OP_MOD]: conditionallyEvaluate(opMod),
          [OpcodesBCH.OP_LSHIFT]: disabledOperation,
          [OpcodesBCH.OP_RSHIFT]: disabledOperation,
          ...mapOverOperations<AuthenticationProgramStateBCH>(
            [conditionallyEvaluate],
            {
              [OpcodesBCH.OP_BOOLAND]: opBoolAnd,
              [OpcodesBCH.OP_BOOLOR]: opBoolOr,
              [OpcodesBCH.OP_NUMEQUAL]: opNumEqual,
              [OpcodesBCH.OP_NUMEQUALVERIFY]: opNumEqualVerify,
              [OpcodesBCH.OP_NUMNOTEQUAL]: opNumNotEqual,
              [OpcodesBCH.OP_LESSTHAN]: opLessThan,
              [OpcodesBCH.OP_GREATERTHAN]: opGreaterThan,
              [OpcodesBCH.OP_LESSTHANOREQUAL]: opLessThanOrEqual,
              [OpcodesBCH.OP_GREATERTHANOREQUAL]: opGreaterThanOrEqual,
              [OpcodesBCH.OP_MIN]: opMin,
              [OpcodesBCH.OP_MAX]: opMax,
              [OpcodesBCH.OP_WITHIN]: opWithin,
              [OpcodesBCH.OP_RIPEMD160]: opRipemd160({ ripemd160 }),
              [OpcodesBCH.OP_SHA1]: opSha1({ sha1 }),
              [OpcodesBCH.OP_SHA256]: opSha256({ sha256 }),
              [OpcodesBCH.OP_HASH160]: opHash160({ ripemd160, sha256 }),
              [OpcodesBCH.OP_HASH256]: opHash256({ sha256 }),
              [OpcodesBCH.OP_CODESEPARATOR]: opCodeSeparator,
              [OpcodesBCH.OP_CHECKSIG]: opCheckSig({ secp256k1, sha256 }),
              [OpcodesBCH.OP_CHECKSIGVERIFY]: opCheckSigVerify({
                secp256k1,
                sha256,
              }),
              [OpcodesBCH.OP_CHECKMULTISIG]: opCheckMultiSig({
                secp256k1,
                sha256,
              }),
              [OpcodesBCH.OP_CHECKMULTISIGVERIFY]: opCheckMultiSigVerify({
                secp256k1,
                sha256,
              }),
              ...(standard
                ? {
                    [OpcodesBCH.OP_NOP1]: opNopDisallowed,
                    [OpcodesBCH.OP_CHECKLOCKTIMEVERIFY]: opCheckLockTimeVerify,
                    [OpcodesBCH.OP_CHECKSEQUENCEVERIFY]: opCheckSequenceVerify,
                    [OpcodesBCH.OP_NOP4]: opNopDisallowed,
                    [OpcodesBCH.OP_NOP5]: opNopDisallowed,
                    [OpcodesBCH.OP_NOP6]: opNopDisallowed,
                    [OpcodesBCH.OP_NOP7]: opNopDisallowed,
                    [OpcodesBCH.OP_NOP8]: opNopDisallowed,
                    [OpcodesBCH.OP_NOP9]: opNopDisallowed,
                    [OpcodesBCH.OP_NOP10]: opNopDisallowed,
                  }
                : {
                    [OpcodesBCH.OP_NOP1]: opNop,
                    [OpcodesBCH.OP_CHECKLOCKTIMEVERIFY]: opCheckLockTimeVerify,
                    [OpcodesBCH.OP_CHECKSEQUENCEVERIFY]: opCheckSequenceVerify,
                    [OpcodesBCH.OP_NOP4]: opNop,
                    [OpcodesBCH.OP_NOP5]: opNop,
                    [OpcodesBCH.OP_NOP6]: opNop,
                    [OpcodesBCH.OP_NOP7]: opNop,
                    [OpcodesBCH.OP_NOP8]: opNop,
                    [OpcodesBCH.OP_NOP9]: opNop,
                    [OpcodesBCH.OP_NOP10]: opNop,
                  }),
              [OpcodesBCH.OP_CHECKDATASIG]: opCheckDataSig({
                secp256k1,
                sha256,
              }),
              [OpcodesBCH.OP_CHECKDATASIGVERIFY]: opCheckDataSigVerify({
                secp256k1,
                sha256,
              }),
              [OpcodesBCH.OP_REVERSEBYTES]: opReverseBytes,
            }
          ),
        }
      ),
    },
    success: (state: AuthenticationProgramStateBCH) => {
      if (state.error !== undefined) {
        return state.error;
      }
      if (state.controlStack.length !== 0) {
        return AuthenticationErrorCommon.nonEmptyControlStack;
      }
      if (state.stack.length !== 1) {
        return AuthenticationErrorCommon.requiresCleanStack;
      }
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      if (!stackItemIsTruthy(state.stack[0]!)) {
        return AuthenticationErrorCommon.unsuccessfulEvaluation;
      }
      return true;
    },
    undefined: undefinedOperation,
    // eslint-disable-next-line complexity
    verify: ({ sourceOutputs, transaction }, evaluate, stateSuccess) => {
      if (transaction.inputs.length !== sourceOutputs.length) {
        return 'Unable to verify transaction: a spent output must be provided for each transaction input.';
      }

      const transactionSize = encodeTransactionBCH(transaction).length;
      if (transactionSize > ConsensusBCH2022.maximumTransactionSize) {
        return `Transaction exceeds maximum size: this transaction is ${transactionSize} bytes, but the maximum transaction size is ${ConsensusBCH2022.maximumTransactionSize} bytes.`;
      }

      if (standard) {
        if (
          transaction.version < 1 ||
          transaction.version > ConsensusBCH2022.maximumStandardVersion
        ) {
          return `Standard transactions must have a version no less than 1 and no greater than ${ConsensusBCH2022.maximumStandardVersion}.`;
        }
        if (transactionSize > ConsensusBCH2022.maximumStandardTransactionSize) {
          return `Transaction exceeds maximum standard size: this transaction is ${transactionSize} bytes, but the maximum standard transaction size is ${ConsensusBCH2022.maximumStandardTransactionSize} bytes.`;
        }

        // eslint-disable-next-line functional/no-loop-statement
        for (const output of sourceOutputs) {
          if (!isStandardOutputBytecode(output.lockingBytecode)) {
            return `Standard transaction may only spend standard output types.`;
          }
        }

        // eslint-disable-next-line functional/no-let
        let totalArbitraryDataBytes = 0;
        // eslint-disable-next-line functional/no-loop-statement
        for (const output of transaction.outputs) {
          if (!isStandardOutputBytecode(output.lockingBytecode)) {
            return `Standard transaction may only create standard output types.`;
          }

          // eslint-disable-next-line functional/no-conditional-statement
          if (isArbitraryDataOutput(output.lockingBytecode)) {
            // eslint-disable-next-line functional/no-expression-statement
            totalArbitraryDataBytes += output.lockingBytecode.length + 1;
          }
          /*
           * TODO: disallow dust outputs
           * if(IsDustOutput(output)) {
           *   return ``;
           * }
           */
        }
        if (
          totalArbitraryDataBytes > ConsensusBCH2022.maximumDataCarrierBytes
        ) {
          return `Standard transactions may carry no more than ${ConsensusBCH2022.maximumDataCarrierBytes} bytes in arbitrary data outputs; this transaction includes ${totalArbitraryDataBytes} bytes of arbitrary data.`;
        }

        // eslint-disable-next-line functional/no-loop-statement
        for (const [inputIndex, input] of transaction.inputs.entries()) {
          if (
            input.unlockingBytecode.length >
            ConsensusBCH2022.maximumStandardUnlockingBytecodeLength
          ) {
            return `Input index ${inputIndex} is non-standard: the unlocking bytecode (${input.unlockingBytecode.length} bytes) exceeds the maximum standard unlocking bytecode length (${ConsensusBCH2022.maximumStandardUnlockingBytecodeLength} bytes).`;
          }
          if (!isPushOnly(input.unlockingBytecode)) {
            return `Input index ${inputIndex} is non-standard: unlocking bytecode may contain only push operations.`;
          }
        }
      }

      // eslint-disable-next-line functional/no-loop-statement
      for (const inputIndex of transaction.inputs.keys()) {
        const state = evaluate({ inputIndex, sourceOutputs, transaction });
        const result = stateSuccess(state);
        if (typeof result === 'string') {
          return `Error in evaluating input index ${inputIndex}: ${result}`;
        }
      }

      return true;
    },
  };
};
