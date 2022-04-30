import type {
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../../vm';
import { combineOperations } from '../../common/common.js';
import {
  applyError,
  AuthenticationErrorCommon,
  bigIntToVmNumber,
  booleanToVmNumber,
  opVerify,
  padMinimallyEncodedVmNumber,
  pushToStack,
  useOneStackItem,
  useOneVmNumber,
  useThreeVmNumbers,
  useTwoVmNumbers,
} from '../../instruction-sets.js';

import { ConsensusBCH2021 } from './bch-2021-types.js';

const maximumVmNumberByteLength = ConsensusBCH2021.maximumVmNumberLength;

export const opPick4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, depth) => {
    const item = nextState.stack[nextState.stack.length - 1 - Number(depth)];
    if (item === undefined) {
      return applyError(AuthenticationErrorCommon.invalidStackIndex, state);
    }
    return pushToStack(nextState, item.slice());
  });

export const opRoll4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, depth) => {
    const index = nextState.stack.length - 1 - Number(depth);
    if (index < 0 || index > nextState.stack.length - 1) {
      return applyError(AuthenticationErrorCommon.invalidStackIndex, state);
    }
    // eslint-disable-next-line functional/immutable-data, @typescript-eslint/no-non-null-assertion
    return pushToStack(nextState, nextState.stack.splice(index, 1)[0]!);
  });

export const opSplit4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, value) => {
      const index = Number(value);
      return useOneStackItem(nextState, (finalState, [item]) =>
        index < 0 || index > item.length
          ? applyError(AuthenticationErrorCommon.invalidSplitIndex, finalState)
          : pushToStack(finalState, item.slice(0, index), item.slice(index))
      );
    },
    { maximumVmNumberByteLength }
  );

export const opNum2Bin4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(state, (nextState, value) => {
    const targetLength = Number(value);
    return targetLength > ConsensusBCH2021.maximumStackItemLength
      ? applyError(
          AuthenticationErrorCommon.exceededMaximumStackItemLength,
          nextState
        )
      : useOneVmNumber(
          nextState,
          (finalState, [target]) => {
            const minimallyEncoded = bigIntToVmNumber(target);
            return minimallyEncoded.length > targetLength
              ? applyError(
                  AuthenticationErrorCommon.insufficientLength,
                  finalState
                )
              : minimallyEncoded.length === targetLength
              ? pushToStack(finalState, minimallyEncoded)
              : pushToStack(
                  finalState,
                  padMinimallyEncodedVmNumber(minimallyEncoded, targetLength)
                );
          },
          {
            maximumVmNumberByteLength: ConsensusBCH2021.maximumStackItemLength,
            requireMinimalEncoding: false,
          }
        );
  });

export const opBin2Num4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [target]) => {
      const minimallyEncoded = bigIntToVmNumber(target);
      return minimallyEncoded.length > ConsensusBCH2021.maximumVmNumberLength
        ? applyError(
            AuthenticationErrorCommon.exceededMaximumVmNumberLength,
            nextState
          )
        : pushToStack(nextState, minimallyEncoded);
    },
    {
      maximumVmNumberByteLength: ConsensusBCH2021.maximumStackItemLength,
      requireMinimalEncoding: false,
    }
  );

export const op1Add4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToVmNumber(value + BigInt(1))),
    { maximumVmNumberByteLength }
  );

export const op1Sub4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToVmNumber(value - BigInt(1))),
    { maximumVmNumberByteLength }
  );

export const opNegate4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [value]) => pushToStack(nextState, bigIntToVmNumber(-value)),
    { maximumVmNumberByteLength }
  );

export const opAbs4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToVmNumber(value < 0 ? -value : value)),
    { maximumVmNumberByteLength }
  );

export const opNot4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [value]) =>
      pushToStack(
        nextState,
        value === BigInt(0)
          ? bigIntToVmNumber(BigInt(1))
          : bigIntToVmNumber(BigInt(0))
      ),
    { maximumVmNumberByteLength }
  );

export const op0NotEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneVmNumber(
    state,
    (nextState, [value]) =>
      pushToStack(
        nextState,
        value === BigInt(0)
          ? bigIntToVmNumber(BigInt(0))
          : bigIntToVmNumber(BigInt(1))
      ),
    { maximumVmNumberByteLength }
  );

export const opAdd4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, bigIntToVmNumber(firstValue + secondValue)),
    { maximumVmNumberByteLength }
  );

export const opSub4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, bigIntToVmNumber(firstValue - secondValue)),
    { maximumVmNumberByteLength }
  );

export const opDiv4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [a, b]) =>
      b === BigInt(0)
        ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
        : pushToStack(nextState, bigIntToVmNumber(a / b)),
    { maximumVmNumberByteLength }
  );

export const opMod4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [a, b]) =>
      b === BigInt(0)
        ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
        : pushToStack(nextState, bigIntToVmNumber(a % b)),
    { maximumVmNumberByteLength }
  );

export const opBoolAnd4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        booleanToVmNumber(firstValue !== BigInt(0) && secondValue !== BigInt(0))
      ),
    { maximumVmNumberByteLength }
  );

export const opBoolOr4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        booleanToVmNumber(firstValue !== BigInt(0) || secondValue !== BigInt(0))
      ),
    { maximumVmNumberByteLength }
  );

export const opNumEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToVmNumber(firstValue === secondValue)),
    { maximumVmNumberByteLength }
  );

export const opNumEqualVerify4Byte = combineOperations(
  opNumEqual4Byte,
  opVerify
);

export const opNumNotEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToVmNumber(firstValue !== secondValue)),
    { maximumVmNumberByteLength }
  );

export const opLessThan4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToVmNumber(firstValue < secondValue)),
    { maximumVmNumberByteLength }
  );

export const opLessThanOrEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToVmNumber(firstValue <= secondValue)),
    { maximumVmNumberByteLength }
  );

export const opGreaterThan4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToVmNumber(firstValue > secondValue)),
    { maximumVmNumberByteLength }
  );

export const opGreaterThanOrEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToVmNumber(firstValue >= secondValue)),
    { maximumVmNumberByteLength }
  );

export const opMin4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        bigIntToVmNumber(firstValue < secondValue ? firstValue : secondValue)
      ),
    { maximumVmNumberByteLength }
  );

export const opMax4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoVmNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        bigIntToVmNumber(firstValue > secondValue ? firstValue : secondValue)
      ),
    { maximumVmNumberByteLength }
  );

export const opWithin4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useThreeVmNumbers(
    state,
    (nextState, [firstValue, secondValue, thirdValue]) =>
      pushToStack(
        nextState,
        booleanToVmNumber(secondValue <= firstValue && firstValue < thirdValue)
      ),
    { maximumVmNumberByteLength }
  );
