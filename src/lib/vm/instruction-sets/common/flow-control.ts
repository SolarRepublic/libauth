import type {
  AuthenticationProgramStateControlStack,
  AuthenticationProgramStateError,
  AuthenticationProgramStateStack,
} from '../../vm';

import {
  applyError,
  AuthenticationErrorCommon,
  stackItemIsTruthy,
  useOneStackItem,
} from './common.js';

export const opVerify = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) =>
  useOneStackItem(state, (nextState, [item]) =>
    stackItemIsTruthy(item)
      ? nextState
      : applyError(AuthenticationErrorCommon.failedVerify, nextState)
  );

export const reservedOperation = <
  State extends AuthenticationProgramStateError
>(
  state: State
) => applyError(AuthenticationErrorCommon.calledReserved, state);

export const opReturn = <State extends AuthenticationProgramStateError>(
  state: State
) => applyError(AuthenticationErrorCommon.calledReturn, state);

export const opIf = <
  State extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) => {
  if (state.controlStack.every((item) => item)) {
    return useOneStackItem(state, (nextState, [item]) => {
      // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
      nextState.controlStack.push(stackItemIsTruthy(item));
      return state;
    });
  }
  // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
  state.controlStack.push(false);
  return state;
};

/**
 * Note, `OP_NOTIF` is not completely equivalent to `OP_NOT OP_IF`. `OP_NOT`
 * operates on a VM Number (as the inverse of `OP_0NOTEQUAL`), while `OP_NOTIF`
 * checks the "truthy-ness" of a stack item like `OP_IF`.
 */
export const opNotIf = <
  State extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateError &
    AuthenticationProgramStateStack
>(
  state: State
) => {
  if (state.controlStack.every((item) => item)) {
    return useOneStackItem(state, (nextState, [item]) => {
      // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
      nextState.controlStack.push(!stackItemIsTruthy(item));
      return state;
    });
  }
  // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
  state.controlStack.push(false);
  return state;
};

export const opEndIf = <
  State extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateError
>(
  state: State
) => {
  // eslint-disable-next-line functional/immutable-data
  const element = state.controlStack.pop();
  if (element === undefined) {
    return applyError(AuthenticationErrorCommon.unexpectedEndIf, state);
  }
  return state;
};

export const opElse = <
  State extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateError
>(
  state: State
) => {
  const top = state.controlStack[state.controlStack.length - 1] as
    | boolean
    | undefined;
  if (top === undefined) {
    return applyError(AuthenticationErrorCommon.unexpectedElse, state);
  }
  // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
  state.controlStack[state.controlStack.length - 1] = !top;
  return state;
};
