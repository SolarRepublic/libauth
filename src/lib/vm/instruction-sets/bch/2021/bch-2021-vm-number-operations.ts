import type {
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../../vm';
import { combineOperations } from '../../common/common.js';
import {
  applyError,
  AuthenticationErrorCommon,
  bigIntToScriptNumber,
  booleanToScriptNumber,
  opVerify,
  padMinimallyEncodedScriptNumber,
  pushToStack,
  useOneScriptNumber,
  useOneStackItem,
  useThreeScriptNumbers,
  useTwoScriptNumbers,
} from '../../instruction-sets.js';

import { ConsensusBCH2021 } from './bch-2021-types.js';

const maximumScriptNumberByteLength =
  ConsensusBCH2021.maximumScriptNumberLength;

export const opPick4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, depth) => {
    const item = nextState.stack[nextState.stack.length - 1 - Number(depth)] as
      | Uint8Array
      | undefined;
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
  useOneScriptNumber(state, (nextState, depth) => {
    const index = nextState.stack.length - 1 - Number(depth);
    if (index < 0 || index > nextState.stack.length - 1) {
      return applyError(AuthenticationErrorCommon.invalidStackIndex, state);
    }
    // eslint-disable-next-line functional/immutable-data
    return pushToStack(nextState, nextState.stack.splice(index, 1)[0]);
  });

export const opSplit4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, value) => {
      const index = Number(value);
      return useOneStackItem(nextState, (finalState, [item]) =>
        index < 0 || index > item.length
          ? applyError(AuthenticationErrorCommon.invalidSplitIndex, finalState)
          : pushToStack(finalState, item.slice(0, index), item.slice(index))
      );
    },
    { maximumScriptNumberByteLength }
  );

export const opNum2Bin4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, value) => {
    const targetLength = Number(value);
    return targetLength > ConsensusBCH2021.maximumStackItemLength
      ? applyError(
          AuthenticationErrorCommon.exceededMaximumStackItemLength,
          nextState
        )
      : useOneScriptNumber(
          nextState,
          (finalState, [target]) => {
            const minimallyEncoded = bigIntToScriptNumber(target);
            return minimallyEncoded.length > targetLength
              ? applyError(
                  AuthenticationErrorCommon.insufficientLength,
                  finalState
                )
              : minimallyEncoded.length === targetLength
              ? pushToStack(finalState, minimallyEncoded)
              : pushToStack(
                  finalState,
                  padMinimallyEncodedScriptNumber(
                    minimallyEncoded,
                    targetLength
                  )
                );
          },
          {
            maximumScriptNumberByteLength:
              ConsensusBCH2021.maximumStackItemLength,
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
  useOneScriptNumber(
    state,
    (nextState, [target]) => {
      const minimallyEncoded = bigIntToScriptNumber(target);
      return minimallyEncoded.length >
        ConsensusBCH2021.maximumScriptNumberLength
        ? applyError(
            AuthenticationErrorCommon.exceededMaximumScriptNumberLength,
            nextState
          )
        : pushToStack(nextState, minimallyEncoded);
    },
    {
      maximumScriptNumberByteLength: ConsensusBCH2021.maximumStackItemLength,
      requireMinimalEncoding: false,
    }
  );

export const op1Add4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToScriptNumber(value + BigInt(1))),
    { maximumScriptNumberByteLength }
  );

export const op1Sub4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToScriptNumber(value - BigInt(1))),
    { maximumScriptNumberByteLength }
  );

export const opNegate4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToScriptNumber(-value)),
    { maximumScriptNumberByteLength }
  );

export const opAbs4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [value]) =>
      pushToStack(nextState, bigIntToScriptNumber(value < 0 ? -value : value)),
    { maximumScriptNumberByteLength }
  );

export const opNot4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [value]) =>
      pushToStack(
        nextState,
        value === BigInt(0)
          ? bigIntToScriptNumber(BigInt(1))
          : bigIntToScriptNumber(BigInt(0))
      ),
    { maximumScriptNumberByteLength }
  );

export const op0NotEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [value]) =>
      pushToStack(
        nextState,
        value === BigInt(0)
          ? bigIntToScriptNumber(BigInt(0))
          : bigIntToScriptNumber(BigInt(1))
      ),
    { maximumScriptNumberByteLength }
  );

export const opAdd4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, bigIntToScriptNumber(firstValue + secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opSub4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, bigIntToScriptNumber(firstValue - secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opDiv4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [a, b]) =>
      b === BigInt(0)
        ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
        : pushToStack(nextState, bigIntToScriptNumber(a / b)),
    { maximumScriptNumberByteLength }
  );

export const opMod4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [a, b]) =>
      b === BigInt(0)
        ? applyError(AuthenticationErrorCommon.divisionByZero, nextState)
        : pushToStack(nextState, bigIntToScriptNumber(a % b)),
    { maximumScriptNumberByteLength }
  );

export const opBoolAnd4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        booleanToScriptNumber(
          firstValue !== BigInt(0) && secondValue !== BigInt(0)
        )
      ),
    { maximumScriptNumberByteLength }
  );

export const opBoolOr4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        booleanToScriptNumber(
          firstValue !== BigInt(0) || secondValue !== BigInt(0)
        )
      ),
    { maximumScriptNumberByteLength }
  );

export const opNumEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToScriptNumber(firstValue === secondValue)),
    { maximumScriptNumberByteLength }
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
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToScriptNumber(firstValue !== secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opLessThan4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToScriptNumber(firstValue < secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opLessThanOrEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToScriptNumber(firstValue <= secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opGreaterThan4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToScriptNumber(firstValue > secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opGreaterThanOrEqual4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(nextState, booleanToScriptNumber(firstValue >= secondValue)),
    { maximumScriptNumberByteLength }
  );

export const opMin4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        bigIntToScriptNumber(
          firstValue < secondValue ? firstValue : secondValue
        )
      ),
    { maximumScriptNumberByteLength }
  );

export const opMax4Byte = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [firstValue, secondValue]) =>
      pushToStack(
        nextState,
        bigIntToScriptNumber(
          firstValue > secondValue ? firstValue : secondValue
        )
      ),
    { maximumScriptNumberByteLength }
  );

export const opWithin4Byte = <
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
      ),
    { maximumScriptNumberByteLength }
  );
