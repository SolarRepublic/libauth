import type {
  AuthenticationVirtualMachine,
  Input,
  Output,
  TransactionCommon as TransactionBCH,
} from '../../../../lib';
import {
  decodeTransactionCommon as decodeTransactionBCH,
  decodeTransactionUnsafeCommon as decodeTransactionUnsafeBCH,
  encodeTransactionCommon as encodeTransactionBCH,
  encodeTransactionCommon,
  hashTransactionP2pOrder,
  hexToBin,
} from '../../../../lib.js';
import type {
  AuthenticationProgramCommon,
  AuthenticationProgramStateCommon,
  ResolvedTransactionCommon,
} from '../../../vm-types';
import type { CompilationContext } from '../../instruction-sets';
import { cloneAuthenticationProgramStateCommon as cloneAuthenticationProgramStateBCH } from '../../instruction-sets.js';

export enum ConsensusBCH2022 {
  /**
   * A.K.A. `MAX_SCRIPT_ELEMENT_SIZE`
   */
  maximumStackItemLength = 520,
  maximumVmNumberLength = 8,
  /**
   * A.K.A. `MAX_OPS_PER_SCRIPT`
   */
  maximumOperationCount = 201,
  /**
   * A.K.A. `MAX_SCRIPT_SIZE`
   */
  maximumBytecodeLength = 10000,
  /**
   * A.K.A. `MAX_STACK_SIZE`
   */
  maximumStackDepth = 1000,
  schnorrSignatureLength = 64,
}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface ResolvedTransactionBCH extends ResolvedTransactionCommon {}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AuthenticationProgramBCH extends AuthenticationProgramCommon {}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AuthenticationProgramStateBCH
  extends AuthenticationProgramStateCommon {}

export type { TransactionBCH };

export {
  cloneAuthenticationProgramStateBCH,
  decodeTransactionBCH,
  encodeTransactionBCH,
  decodeTransactionUnsafeBCH,
};

export type CompilationContextBCH = CompilationContext<
  TransactionBCH<Input<Uint8Array | undefined>>
>;

export type AuthenticationVirtualMachineBCH = AuthenticationVirtualMachine<
  ResolvedTransactionBCH,
  AuthenticationProgramBCH,
  AuthenticationProgramStateBCH
>;

export const createTestAuthenticationProgramBCH = ({
  lockingBytecode,
  valueSatoshis,
  unlockingBytecode,
}: Output & Pick<Input, 'unlockingBytecode'>) => {
  const testFundingTransaction: TransactionBCH = {
    inputs: [
      {
        outpointIndex: 0xffffffff,
        outpointTransactionHash: hexToBin(
          '0000000000000000000000000000000000000000000000000000000000000000'
        ),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: Uint8Array.of(0, 0),
      },
    ],
    locktime: 0,
    outputs: [{ lockingBytecode, valueSatoshis }],
    version: 1,
  };
  const testSpendingTransaction: TransactionBCH = {
    inputs: [
      {
        outpointIndex: 0,
        outpointTransactionHash: hashTransactionP2pOrder(
          encodeTransactionCommon(testFundingTransaction)
        ),

        sequenceNumber: 0xffffffff,
        unlockingBytecode,
      },
    ],
    locktime: 0,
    outputs: [{ lockingBytecode: Uint8Array.of(), valueSatoshis }],
    version: 1,
  };
  return {
    inputIndex: 0,
    sourceOutputs: testFundingTransaction.outputs,
    transaction: testSpendingTransaction,
  };
};
