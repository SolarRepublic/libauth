import type { AuthenticationProgramStateError } from '../../vm';

import { applyError, AuthenticationErrorCommon } from './common.js';

export const opNop = <State>(state: State) => state;

export const opNopDisallowed = <State>(state: State) =>
  applyError(AuthenticationErrorCommon.calledUpgradableNop, state);

/**
 * "Disabled" operations are explicitly forbidden from occurring anywhere in VM
 * bytecode, even within an unexecuted branch.
 */
export const disabledOperation = <
  State extends AuthenticationProgramStateError
>(
  state: State
) => applyError(AuthenticationErrorCommon.unknownOpcode, state);
