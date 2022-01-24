import type {
  AuthenticationProgramStateCommon,
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../vm';

import {
  applyError,
  AuthenticationErrorCommon,
  isScriptNumberError,
  parseBytesAsScriptNumber,
} from './common.js';

enum Bits {
  sequenceLocktimeDisableFlag = 31,
  sequenceLocktimeTypeFlag = 22,
}

enum Constants {
  locktimeScriptNumberByteLength = 5,
  locktimeThreshold = 500_000_000,
  locktimeDisablingSequenceNumber = 0xffffffff,
  sequenceLocktimeTransactionVersionMinimum = 2,
  // eslint-disable-next-line no-bitwise, @typescript-eslint/prefer-literal-enum-member
  sequenceLocktimeDisableFlag = (1 << Bits.sequenceLocktimeDisableFlag) >>> 0,
  // eslint-disable-next-line no-bitwise, @typescript-eslint/prefer-literal-enum-member
  sequenceLocktimeTypeFlag = 1 << Bits.sequenceLocktimeTypeFlag,
  sequenceGranularity = 9,
  sequenceLocktimeMask = 0x0000ffff,
}

export const readLocktime = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (nextState: State, locktime: number) => State
) => {
  const item = state.stack[state.stack.length - 1] as Uint8Array | undefined;
  if (item === undefined) {
    return applyError(AuthenticationErrorCommon.emptyStack, state);
  }
  const parsedLocktime = parseBytesAsScriptNumber(item, {
    maximumScriptNumberByteLength: Constants.locktimeScriptNumberByteLength,
    requireMinimalEncoding: true,
  });
  if (isScriptNumberError(parsedLocktime)) {
    return applyError(AuthenticationErrorCommon.invalidScriptNumber, state);
  }
  const locktime = Number(parsedLocktime);
  if (locktime < 0) {
    return applyError(AuthenticationErrorCommon.negativeLocktime, state);
  }
  return operation(state, locktime);
};

const locktimeTypesAreCompatible = (
  locktime: number,
  requiredLocktime: number
) =>
  (locktime < Constants.locktimeThreshold &&
    requiredLocktime < Constants.locktimeThreshold) ||
  (locktime >= Constants.locktimeThreshold &&
    requiredLocktime >= Constants.locktimeThreshold);

export const opCheckLockTimeVerify = <
  State extends AuthenticationProgramStateCommon
>(
  state: State
) =>
  readLocktime(state, (nextState, requiredLocktime) => {
    if (
      !locktimeTypesAreCompatible(
        nextState.program.transaction.locktime,
        requiredLocktime
      )
    ) {
      return applyError(
        AuthenticationErrorCommon.incompatibleLocktimeType,
        nextState
      );
    }
    if (requiredLocktime > nextState.program.transaction.locktime) {
      return applyError(
        AuthenticationErrorCommon.unsatisfiedLocktime,
        nextState
      );
    }
    const { sequenceNumber } =
      nextState.program.transaction.inputs[nextState.program.inputIndex];
    if (sequenceNumber === Constants.locktimeDisablingSequenceNumber) {
      return applyError(AuthenticationErrorCommon.locktimeDisabled, nextState);
    }
    return nextState;
  });

// eslint-disable-next-line no-bitwise
const includesFlag = (value: number, flag: number) => (value & flag) !== 0;

export const opCheckSequenceVerify = <
  State extends AuthenticationProgramStateCommon
>(
  state: State
) =>
  readLocktime(
    state,
    // eslint-disable-next-line complexity
    (nextState, requiredSequence) => {
      const { sequenceNumber } =
        nextState.program.transaction.inputs[nextState.program.inputIndex];
      const sequenceLocktimeDisabled = includesFlag(
        requiredSequence,
        Constants.sequenceLocktimeDisableFlag
      );
      if (sequenceLocktimeDisabled) {
        return nextState;
      }

      if (
        nextState.program.transaction.version <
        Constants.sequenceLocktimeTransactionVersionMinimum
      ) {
        return applyError(
          AuthenticationErrorCommon.checkSequenceUnavailable,
          nextState
        );
      }

      if (includesFlag(sequenceNumber, Constants.sequenceLocktimeDisableFlag)) {
        return applyError(
          AuthenticationErrorCommon.unmatchedSequenceDisable,
          nextState
        );
      }

      if (
        includesFlag(requiredSequence, Constants.sequenceLocktimeTypeFlag) !==
        includesFlag(sequenceNumber, Constants.sequenceLocktimeTypeFlag)
      ) {
        return applyError(
          AuthenticationErrorCommon.incompatibleSequenceType,
          nextState
        );
      }

      if (
        // eslint-disable-next-line no-bitwise
        (requiredSequence & Constants.sequenceLocktimeMask) >
        // eslint-disable-next-line no-bitwise
        (sequenceNumber & Constants.sequenceLocktimeMask)
      ) {
        return applyError(
          AuthenticationErrorCommon.unsatisfiedSequenceNumber,
          nextState
        );
      }

      return nextState;
    }
  );
