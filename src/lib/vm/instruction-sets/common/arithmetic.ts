import type {
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../vm';

import {
  combineOperations,
  useOneVmNumber,
  useThreeVmNumbers,
  useTwoVmNumbers,
} from './combinators.js';
import {
  applyError,
  AuthenticationErrorCommon,
  bigIntToVmNumber,
  booleanToVmNumber,
  pushToStack,
} from './common.js';
import { opVerify } from './flow-control.js';

export const op1Add = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToVmNumber(value + BigInt(1)))
  );

export const op1Sub = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToVmNumber(value - BigInt(1)))
  );

export const opNegate = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToVmNumber(-value))
  );

export const opAbs = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToVmNumber(value < 0 ? -value : value))
  );

export const opNot = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, [value]) =>
    pushToStack(
      nextState,
      value === BigInt(0)
        ? bigIntToVmNumber(BigInt(1))
        : bigIntToVmNumber(BigInt(0))
    )
  );

export const op0NotEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, [value]) =>
    pushToStack(
      nextState,
      value === BigInt(0)
        ? bigIntToVmNumber(BigInt(0))
        : bigIntToVmNumber(BigInt(1))
    )
  );

export const opAdd = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, bigIntToVmNumber(firstValue + secondValue))
  );

export const opSub = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, bigIntToVmNumber(firstValue - secondValue))
  );

export const opBoolAnd = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      booleanToVmNumber(firstValue !== BigInt(0) && secondValue !== BigInt(0))
    )
  );

export const opBoolOr = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      booleanToVmNumber(firstValue !== BigInt(0) || secondValue !== BigInt(0))
    )
  );

export const opNumEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToVmNumber(firstValue === secondValue))
  );

export const opNumEqualVerify = combineOperations(opNumEqual, opVerify);

export const opNumNotEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToVmNumber(firstValue !== secondValue))
  );

export const opLessThan = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToVmNumber(firstValue < secondValue))
  );

export const opLessThanOrEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToVmNumber(firstValue <= secondValue))
  );

export const opGreaterThan = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToVmNumber(firstValue > secondValue))
  );

export const opGreaterThanOrEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToVmNumber(firstValue >= secondValue))
  );

export const opMin = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      bigIntToVmNumber(firstValue < secondValue ? firstValue : secondValue)
    )
  );

export const opMax = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      bigIntToVmNumber(firstValue > secondValue ? firstValue : secondValue)
    )
  );

export const opWithin = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useThreeVmNumbers(state, (nextState, [firstValue, secondValue, thirdValue]) =>
    pushToStack(
      nextState,
      booleanToVmNumber(secondValue <= firstValue && firstValue < thirdValue)
    )
  );

export const opDiv = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [a, b]) =>
    b === BigInt(0)
      ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
      : pushToStack(nextState, bigIntToVmNumber(a / b))
  );

export const opMod = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(state, (nextState, [a, b]) =>
    b === BigInt(0)
      ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
      : pushToStack(nextState, bigIntToVmNumber(a % b))
  );
