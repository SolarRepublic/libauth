import type {
  AuthenticationProgramStateControlStack,
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
  InstructionSetOperationMapping,
  Operation,
} from '../../vm';

import {
  applyError,
  AuthenticationErrorCommon,
  decodeVmNumber,
  isVmNumberError,
} from './common.js';

export const incrementOperationCount =
  <State extends { operationCount: number }>(
    operation: Operation<State>
  ): Operation<State> =>
  (state: State) => {
    const nextState = operation(state);
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    nextState.operationCount += 1;
    return nextState;
  };

export const conditionallyEvaluate =
  <State extends AuthenticationProgramStateControlStack>(
    operation: Operation<State>
  ): Operation<State> =>
  (state: State) =>
    state.controlStack.every((item) => item) ? operation(state) : state;

/**
 * Map a function over each operation in an {@link InstructionSet.operations}
 * object, assigning the result to the same `opcode` in the resulting object.
 * @param operationMap - an operations map from an {@link InstructionSet}
 * @param combinators - a list of functions to apply (in order) to
 * each operation
 */
export const mapOverOperations = <State>(
  combinators: ((operation: Operation<State>) => Operation<State>)[],
  operationMap: InstructionSetOperationMapping<State>
) =>
  Object.keys(operationMap).reduce<InstructionSetOperationMapping<State>>(
    (result, opcode) => ({
      ...result,
      [opcode]: combinators.reduce<Operation<State>>(
        (op, combinator) => combinator(op),
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        operationMap[Number(opcode)]!
      ),
    }),
    {}
  );

/**
 * Pop one stack item off of `state.stack` and provide that item to `operation`.
 */
export const useOneStackItem = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (nextState: State, [value]: [Uint8Array]) => State
) => {
  // eslint-disable-next-line functional/immutable-data
  const item = state.stack.pop();
  if (item === undefined) {
    return applyError(AuthenticationErrorCommon.emptyStack, state);
  }
  return operation(state, [item]);
};

export const useTwoStackItems = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [valueTop, valueTwo]: [Uint8Array, Uint8Array]
  ) => State
) =>
  useOneStackItem(state, (nextState, [valueTwo]) =>
    useOneStackItem(nextState, (lastState, [valueTop]) =>
      operation(lastState, [valueTop, valueTwo])
    )
  );

export const useThreeStackItems = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [valueTop, valueTwo, valueThree]: [Uint8Array, Uint8Array, Uint8Array]
  ) => State
) =>
  useOneStackItem(state, (nextState, [valueThree]) =>
    useTwoStackItems(nextState, (lastState, [valueTop, valueTwo]) =>
      operation(lastState, [valueTop, valueTwo, valueThree])
    )
  );

export const useFourStackItems = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [valueTop, valueTwo, valueThree, valueFour]: [
      Uint8Array,
      Uint8Array,
      Uint8Array,
      Uint8Array
    ]
  ) => State
) =>
  useTwoStackItems(state, (nextState, [valueThree, valueFour]) =>
    useTwoStackItems(nextState, (lastState, [valueTop, valueTwo]) =>
      operation(lastState, [valueTop, valueTwo, valueThree, valueFour])
    )
  );

export const useSixStackItems = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [valueTop, valueTwo, valueThree, valueFour, valueFive, valueSix]: [
      Uint8Array,
      Uint8Array,
      Uint8Array,
      Uint8Array,
      Uint8Array,
      Uint8Array
    ]
  ) => State
) =>
  useFourStackItems(
    state,
    (nextState, [valueThree, valueFour, valueFive, valueSix]) =>
      useTwoStackItems(nextState, (lastState, [valueTop, valueTwo]) =>
        operation(lastState, [
          valueTop,
          valueTwo,
          valueThree,
          valueFour,
          valueFive,
          valueSix,
        ])
      )
  );

const typicalMaximumVmNumberByteLength = 8;

export const useOneVmNumber = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (nextState: State, [value]: [bigint]) => State,
  {
    maximumVmNumberByteLength = typicalMaximumVmNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    maximumVmNumberByteLength?: number;
    requireMinimalEncoding?: boolean;
  } = {
    maximumVmNumberByteLength: typicalMaximumVmNumberByteLength,
    requireMinimalEncoding: true,
  }
) =>
  useOneStackItem(state, (nextState, [item]) => {
    const value = decodeVmNumber(item, {
      maximumVmNumberByteLength,
      requireMinimalEncoding,
    });
    if (isVmNumberError(value)) {
      return applyError(AuthenticationErrorCommon.invalidVmNumber, state);
    }
    return operation(nextState, [value]);
  });

export const useTwoVmNumbers = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [firstValue, secondValue]: [bigint, bigint]
  ) => State,
  {
    maximumVmNumberByteLength = typicalMaximumVmNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    maximumVmNumberByteLength?: number;
    requireMinimalEncoding?: boolean;
  } = {
    maximumVmNumberByteLength: typicalMaximumVmNumberByteLength,
    requireMinimalEncoding: true,
  }
) =>
  useOneVmNumber(
    state,
    (nextState, [secondValue]) =>
      useOneVmNumber(
        nextState,
        (lastState, [firstValue]) =>
          operation(lastState, [firstValue, secondValue]),
        {
          maximumVmNumberByteLength,
          requireMinimalEncoding,
        }
      ),
    {
      maximumVmNumberByteLength,
      requireMinimalEncoding,
    }
  );

export const useThreeVmNumbers = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [firstValue, secondValue, thirdValue]: [bigint, bigint, bigint]
  ) => State,
  {
    maximumVmNumberByteLength = typicalMaximumVmNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    maximumVmNumberByteLength?: number;
    requireMinimalEncoding?: boolean;
  } = {
    maximumVmNumberByteLength: typicalMaximumVmNumberByteLength,
    requireMinimalEncoding: true,
  }
) =>
  useTwoVmNumbers(
    state,
    (nextState, [secondValue, thirdValue]) =>
      useOneVmNumber(
        nextState,
        (lastState, [firstValue]) =>
          operation(lastState, [firstValue, secondValue, thirdValue]),
        {
          maximumVmNumberByteLength,
          requireMinimalEncoding,
        }
      ),
    {
      maximumVmNumberByteLength,
      requireMinimalEncoding,
    }
  );

/**
 * Return the provided state with the provided value pushed to its stack.
 * @param state - the state to update and return
 * @param data - the value to push to the stack
 */
export const pushToStack = <State extends AuthenticationProgramStateStack>(
  state: State,
  ...data: Uint8Array[]
) => {
  // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
  state.stack.push(...data);
  return state;
};

export const combineOperations =
  <State>(
    firstOperation: Operation<State>,
    secondOperation: Operation<State>
  ) =>
  (state: State) =>
    secondOperation(firstOperation(state));
