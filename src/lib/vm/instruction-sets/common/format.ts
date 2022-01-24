import { flattenBinArray } from '../../../lib.js';
import type {
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../vm-types';
import {
  applyError,
  bigIntToScriptNumber,
  ConsensusCommon,
  pushToStack,
  useOneScriptNumber,
  useOneStackItem,
  useTwoStackItems,
} from '../instruction-sets.js';

import { AuthenticationErrorCommon } from './errors.js';

export const opCat = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useTwoStackItems(state, (nextState, [a, b]) =>
    a.length + b.length > ConsensusCommon.maximumStackItemLength
      ? applyError(
          AuthenticationErrorCommon.exceededMaximumStackItemLength,
          nextState
        )
      : pushToStack(nextState, flattenBinArray([a, b]))
  );

export const opSplit = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, value) => {
    const index = Number(value);
    return useOneStackItem(nextState, (finalState, [item]) =>
      index < 0 || index > item.length
        ? applyError(AuthenticationErrorCommon.invalidSplitIndex, finalState)
        : pushToStack(finalState, item.slice(0, index), item.slice(index))
    );
  });

enum Constants {
  positiveSign = 0x00,
  negativeSign = 0x80,
}

export const padMinimallyEncodedScriptNumber = (
  scriptNumber: Uint8Array,
  length: number
) => {
  // eslint-disable-next-line functional/no-let
  let signBit = Constants.positiveSign;
  // eslint-disable-next-line functional/no-conditional-statement
  if (scriptNumber.length > 0) {
    // eslint-disable-next-line functional/no-expression-statement, no-bitwise
    signBit = scriptNumber[scriptNumber.length - 1] & Constants.negativeSign;
    // eslint-disable-next-line functional/no-expression-statement, no-bitwise, functional/immutable-data
    scriptNumber[scriptNumber.length - 1] &= Constants.negativeSign - 1;
  }
  const result = Array.from(scriptNumber);
  // eslint-disable-next-line functional/no-loop-statement
  while (result.length < length - 1) {
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    result.push(0);
  }
  // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
  result.push(signBit);
  return Uint8Array.from(result);
};

export const opNum2Bin = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(state, (nextState, value) => {
    const targetLength = Number(value);
    return targetLength > ConsensusCommon.maximumStackItemLength
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
              // TODO: is this right?
              ConsensusCommon.maximumStackItemLength,
            requireMinimalEncoding: false,
          }
        );
  });

export const opBin2Num = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneScriptNumber(
    state,
    (nextState, [target]) => {
      const minimallyEncoded = bigIntToScriptNumber(target);
      return minimallyEncoded.length > ConsensusCommon.maximumScriptNumberLength
        ? applyError(
            AuthenticationErrorCommon.exceededMaximumScriptNumberLength,
            nextState
          )
        : pushToStack(nextState, minimallyEncoded);
    },
    {
      // TODO: is this right?
      maximumScriptNumberByteLength: ConsensusCommon.maximumStackItemLength,
      requireMinimalEncoding: false,
    }
  );
