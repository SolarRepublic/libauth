import type { AuthenticationProgramStateCommon } from '../../vm';

export interface SegWitState {
  readonly witnessBytecode: Uint8Array;
}

export interface AuthenticationProgramStateBTC
  extends AuthenticationProgramStateCommon,
    SegWitState {}
