import type {
  Input,
  Output,
  Sha256,
  TransactionCommon as TransactionBCH,
} from '../../../../lib';
import {
  encodeTransactionCommon,
  getTransactionHashBE,
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
  maximumScriptNumberLength = 8,
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

export { cloneAuthenticationProgramStateBCH };

export type CompilationContextBCH = CompilationContext<
  TransactionBCH<Input<Uint8Array | undefined>>
>;

export const createTestAuthenticationProgramBCH = ({
  lockingBytecode,
  valueSatoshis,
  sha256,
  unlockingBytecode,
}: Output &
  Pick<Input, 'unlockingBytecode'> & {
    /**
     * An implementation of sha256. Available via `instantiateSha256`.
     */
    sha256: { hash: Sha256['hash'] };
  }) => {
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
        outpointTransactionHash: getTransactionHashBE(
          sha256,
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
