import type { AuthenticationProgramStateStack } from '../../vm';

import {
  bigIntToScriptNumber,
  pushToStack,
  useOneStackItem,
} from './common.js';

export const opSize = <State extends AuthenticationProgramStateStack>(
  state: State
) =>
  useOneStackItem(state, (nextState, [item]) =>
    pushToStack(nextState, item, bigIntToScriptNumber(BigInt(item.length)))
  );
