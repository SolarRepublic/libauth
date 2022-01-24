import type {
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../vm';

import {
  combineOperations,
  useOneScriptNumber,
  useThreeScriptNumbers,
  useTwoScriptNumbers,
} from './combinators.js';
import {
  applyError,
  AuthenticationErrorCommon,
  bigIntToScriptNumber,
  booleanToScriptNumber,
  pushToStack,
} from './common.js';
import { opVerify } from './flow-control.js';

export const op1Add = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToScriptNumber(value + BigInt(1)))
  );

export const op1Sub = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToScriptNumber(value - BigInt(1)))
  );

export const opNegate = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToScriptNumber(-value))
  );

export const opAbs = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, [value]) =>
    pushToStack(nextState, bigIntToScriptNumber(value < 0 ? -value : value))
  );

export const opNot = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, [value]) =>
    pushToStack(
      nextState,
      value === BigInt(0)
        ? bigIntToScriptNumber(BigInt(1))
        : bigIntToScriptNumber(BigInt(0))
    )
  );

export const op0NotEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, [value]) =>
    pushToStack(
      nextState,
      value === BigInt(0)
        ? bigIntToScriptNumber(BigInt(0))
        : bigIntToScriptNumber(BigInt(1))
    )
  );

export const opAdd = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, bigIntToScriptNumber(firstValue + secondValue))
  );

export const opSub = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, bigIntToScriptNumber(firstValue - secondValue))
  );

export const opBoolAnd = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      booleanToScriptNumber(
        firstValue !== BigInt(0) && secondValue !== BigInt(0)
      )
    )
  );

export const opBoolOr = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      booleanToScriptNumber(
        firstValue !== BigInt(0) || secondValue !== BigInt(0)
      )
    )
  );

export const opNumEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToScriptNumber(firstValue === secondValue))
  );

export const opNumEqualVerify = combineOperations(opNumEqual, opVerify);

export const opNumNotEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToScriptNumber(firstValue !== secondValue))
  );

export const opLessThan = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToScriptNumber(firstValue < secondValue))
  );

export const opLessThanOrEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToScriptNumber(firstValue <= secondValue))
  );

export const opGreaterThan = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToScriptNumber(firstValue > secondValue))
  );

export const opGreaterThanOrEqual = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(nextState, booleanToScriptNumber(firstValue >= secondValue))
  );

export const opMin = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      bigIntToScriptNumber(firstValue < secondValue ? firstValue : secondValue)
    )
  );

export const opMax = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [firstValue, secondValue]) =>
    pushToStack(
      nextState,
      bigIntToScriptNumber(firstValue > secondValue ? firstValue : secondValue)
    )
  );

export const opWithin = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useThreeScriptNumbers(
    state,
    (nextState, [firstValue, secondValue, thirdValue]) =>
      pushToStack(
        nextState,
        booleanToScriptNumber(
          secondValue <= firstValue && firstValue < thirdValue
        )
      )
  );

export const opDiv = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [a, b]) =>
    b === BigInt(0)
      ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
      : pushToStack(nextState, bigIntToScriptNumber(a / b))
  );

export const opMod = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(state, (nextState, [a, b]) =>
    b === BigInt(0)
      ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
      : pushToStack(nextState, bigIntToScriptNumber(a % b))
  );
