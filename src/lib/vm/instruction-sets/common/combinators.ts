import type {
  AuthenticationProgramStateError,
  AuthenticationProgramStateExecutionStack,
  AuthenticationProgramStateStack,
  InstructionSetOperationMapping,
  Operation,
} from '../../vm';

import {
  applyError,
  AuthenticationErrorCommon,
  isScriptNumberError,
  parseBytesAsScriptNumber,
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
  <State extends AuthenticationProgramStateExecutionStack>(
    operation: Operation<State>
  ): Operation<State> =>
  (state: State) =>
    state.executionStack.every((item) => item) ? operation(state) : state;

/**
 * Map a function over each operation in an `InstructionSet.operations` object,
 * assigning the result to the same `opcode` in the resulting object.
 * @param operations - an operations map from an `InstructionSet`
 * @param combinator - a function to apply to each operation
 */
export const mapOverOperations = <State>(
  combinators: ((operation: Operation<State>) => Operation<State>)[],
  operations: InstructionSetOperationMapping<State>
) =>
  Object.keys(operations).reduce<{ [opcode: number]: Operation<State> }>(
    (result, operation) => ({
      ...result,
      [operation]: combinators.reduce(
        (op, combinator) => combinator(op),
        operations[parseInt(operation, 10)]
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

const typicalMaximumScriptNumberByteLength = 8;

export const useOneScriptNumber = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (nextState: State, [value]: [bigint]) => State,
  {
    maximumScriptNumberByteLength = typicalMaximumScriptNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    maximumScriptNumberByteLength?: number;
    requireMinimalEncoding?: boolean;
  } = {
    maximumScriptNumberByteLength: typicalMaximumScriptNumberByteLength,
    requireMinimalEncoding: true,
  }
) =>
  useOneStackItem(state, (nextState, [item]) => {
    const value = parseBytesAsScriptNumber(item, {
      maximumScriptNumberByteLength,
      requireMinimalEncoding,
    });
    if (isScriptNumberError(value)) {
      return applyError(AuthenticationErrorCommon.invalidScriptNumber, state);
    }
    return operation(nextState, [value]);
  });

export const useTwoScriptNumbers = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [firstValue, secondValue]: [bigint, bigint]
  ) => State,
  {
    maximumScriptNumberByteLength = typicalMaximumScriptNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    maximumScriptNumberByteLength?: number;
    requireMinimalEncoding?: boolean;
  } = {
    maximumScriptNumberByteLength: typicalMaximumScriptNumberByteLength,
    requireMinimalEncoding: true,
  }
) =>
  useOneScriptNumber(
    state,
    (nextState, [secondValue]) =>
      useOneScriptNumber(
        nextState,
        (lastState, [firstValue]) =>
          operation(lastState, [firstValue, secondValue]),
        { maximumScriptNumberByteLength, requireMinimalEncoding }
      ),
    { maximumScriptNumberByteLength, requireMinimalEncoding }
  );

export const useThreeScriptNumbers = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State,
  operation: (
    nextState: State,
    [firstValue, secondValue, thirdValue]: [bigint, bigint, bigint]
  ) => State,
  {
    maximumScriptNumberByteLength = typicalMaximumScriptNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    maximumScriptNumberByteLength?: number;
    requireMinimalEncoding?: boolean;
  } = {
    maximumScriptNumberByteLength: typicalMaximumScriptNumberByteLength,
    requireMinimalEncoding: true,
  }
) =>
  useTwoScriptNumbers(
    state,
    (nextState, [secondValue, thirdValue]) =>
      useOneScriptNumber(
        nextState,
        (lastState, [firstValue]) =>
          operation(lastState, [firstValue, secondValue, thirdValue]),
        { maximumScriptNumberByteLength, requireMinimalEncoding }
      ),
    { maximumScriptNumberByteLength, requireMinimalEncoding }
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
