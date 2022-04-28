import {
  ripemd160 as internalRipemd160,
  secp256k1 as internalSecp256k1,
  sha1 as internalSha1,
  sha256 as internalSha256,
} from '../../../crypto/default-crypto-instances.js';
import type { Ripemd160, Secp256k1, Sha1, Sha256 } from '../../../lib';
import type {
  AuthenticationProgramStateCommon,
  AuthenticationProgramStateError,
  AuthenticationProgramStateMinimum,
  AuthenticationProgramStateSignatureAnalysis,
  AuthenticationProgramStateStack,
  Operation,
} from '../../vm';
import { encodeAuthenticationInstructions } from '../instruction-sets.js';

import {
  applyError,
  AuthenticationErrorCommon,
  booleanToVmNumber,
  combineOperations,
  ConsensusCommon,
  decodeBitcoinSignature,
  generateSigningSerializationBCH,
  isValidPublicKeyEncoding,
  isValidSignatureEncodingBCHTransaction,
  isValidSignatureEncodingDER,
  opVerify,
  pushToStack,
  useOneStackItem,
  useOneVmNumber,
  useThreeStackItems,
  useTwoStackItems,
} from './common.js';

export const opRipemd160 =
  <
    State extends AuthenticationProgramStateError &
      AuthenticationProgramStateMinimum &
      AuthenticationProgramStateStack
  >(
    {
      ripemd160,
    }: {
      ripemd160: { hash: Ripemd160['hash'] };
    } = { ripemd160: internalRipemd160 }
  ): Operation<State> =>
  (state: State) =>
    useOneStackItem(state, (nextState, [value]) =>
      pushToStack(nextState, ripemd160.hash(value))
    );

export const opSha1 =
  <
    State extends AuthenticationProgramStateError &
      AuthenticationProgramStateMinimum &
      AuthenticationProgramStateStack
  >(
    {
      sha1,
    }: {
      sha1: { hash: Sha1['hash'] };
    } = { sha1: internalSha1 }
  ): Operation<State> =>
  (state: State) =>
    useOneStackItem(state, (nextState, [value]) =>
      pushToStack(nextState, sha1.hash(value))
    );

export const opSha256 =
  <
    State extends AuthenticationProgramStateError &
      AuthenticationProgramStateMinimum &
      AuthenticationProgramStateStack
  >(
    {
      sha256,
    }: {
      sha256: {
        hash: Sha256['hash'];
      };
    } = { sha256: internalSha256 }
  ): Operation<State> =>
  (state: State) =>
    useOneStackItem(state, (nextState, [value]) =>
      pushToStack(nextState, sha256.hash(value))
    );

export const opHash160 =
  <
    State extends AuthenticationProgramStateError &
      AuthenticationProgramStateMinimum &
      AuthenticationProgramStateStack
  >(
    {
      ripemd160,
      sha256,
    }: {
      sha256: { hash: Sha256['hash'] };
      ripemd160: { hash: Ripemd160['hash'] };
    } = { ripemd160: internalRipemd160, sha256: internalSha256 }
  ): Operation<State> =>
  (state: State) =>
    useOneStackItem(state, (nextState, [value]) =>
      pushToStack(nextState, ripemd160.hash(sha256.hash(value)))
    );

export const opHash256 =
  <
    State extends AuthenticationProgramStateError &
      AuthenticationProgramStateMinimum &
      AuthenticationProgramStateStack
  >(
    {
      sha256,
    }: {
      sha256: {
        hash: Sha256['hash'];
      };
    } = { sha256: internalSha256 }
  ): Operation<State> =>
  (state: State) =>
    useOneStackItem(state, (nextState, [value]) =>
      pushToStack(nextState, sha256.hash(sha256.hash(value)))
    );

export const opCodeSeparator = <
  State extends AuthenticationProgramStateMinimum & {
    lastCodeSeparator: number;
  }
>(
  state: State
) => {
  // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
  state.lastCodeSeparator = state.ip;
  return state;
};

export const opCheckSig =
  <State extends AuthenticationProgramStateCommon>(
    {
      secp256k1,
      sha256,
    }: {
      sha256: { hash: Sha256['hash'] };
      secp256k1: {
        verifySignatureSchnorr: Secp256k1['verifySignatureSchnorr'];
        verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
      };
    } = { secp256k1: internalSecp256k1, sha256: internalSha256 }
  ): Operation<State> =>
  (s: State) =>
    // eslint-disable-next-line complexity
    useTwoStackItems(s, (state, [bitcoinEncodedSignature, publicKey]) => {
      if (!isValidPublicKeyEncoding(publicKey)) {
        return applyError(
          AuthenticationErrorCommon.invalidPublicKeyEncoding,
          state
        );
      }
      if (!isValidSignatureEncodingBCHTransaction(bitcoinEncodedSignature)) {
        return applyError(
          AuthenticationErrorCommon.invalidSignatureEncoding,
          state
        );
      }
      const coveredBytecode = encodeAuthenticationInstructions(
        state.instructions
      ).subarray(state.lastCodeSeparator + 1);
      const { signingSerializationType, signature } = decodeBitcoinSignature(
        bitcoinEncodedSignature
      );

      const serialization = generateSigningSerializationBCH(
        state.program,
        { coveredBytecode, signingSerializationType },
        sha256
      );
      const digest = sha256.hash(sha256.hash(serialization));

      // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
      state.signedMessages.push(serialization);

      const useSchnorr =
        signature.length === ConsensusCommon.schnorrSignatureLength;
      const success = useSchnorr
        ? secp256k1.verifySignatureSchnorr(signature, publicKey, digest)
        : secp256k1.verifySignatureDERLowS(signature, publicKey, digest);

      return !success && signature.length !== 0
        ? applyError(AuthenticationErrorCommon.nonNullSignatureFailure, state)
        : pushToStack(state, booleanToVmNumber(success));
    });

const enum Multisig {
  maximumPublicKeys = 20,
}

// TODO: implement schnorr multisig https://gitlab.com/bitcoin-cash-node/bchn-sw/bitcoincash-upgrade-specifications/-/blob/master/spec/2019-11-15-schnorrmultisig.md
export const opCheckMultiSig =
  <State extends AuthenticationProgramStateCommon>(
    {
      secp256k1,
      sha256,
    }: {
      sha256: { hash: Sha256['hash'] };
      secp256k1: {
        verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
      };
    } = { secp256k1: internalSecp256k1, sha256: internalSha256 }
  ) =>
  (s: State) =>
    useOneVmNumber(s, (state, publicKeysValue) => {
      const potentialPublicKeys = Number(publicKeysValue);

      if (potentialPublicKeys < 0) {
        return applyError(
          AuthenticationErrorCommon.invalidNaturalNumber,
          state
        );
      }
      if (potentialPublicKeys > Multisig.maximumPublicKeys) {
        return applyError(
          AuthenticationErrorCommon.exceedsMaximumMultisigPublicKeyCount,
          state
        );
      }
      const publicKeys =
        // eslint-disable-next-line functional/immutable-data
        potentialPublicKeys > 0 ? state.stack.splice(-potentialPublicKeys) : [];

      // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
      state.operationCount += potentialPublicKeys;

      return state.operationCount > ConsensusCommon.maximumOperationCount
        ? applyError(
            AuthenticationErrorCommon.exceededMaximumOperationCount,
            state
          )
        : useOneVmNumber(
            state,

            (nextState, approvingKeys) => {
              const requiredApprovingPublicKeys = Number(approvingKeys);

              if (requiredApprovingPublicKeys < 0) {
                return applyError(
                  AuthenticationErrorCommon.invalidNaturalNumber,
                  nextState
                );
              }

              if (requiredApprovingPublicKeys > potentialPublicKeys) {
                return applyError(
                  AuthenticationErrorCommon.insufficientPublicKeys,
                  nextState
                );
              }

              const signatures =
                requiredApprovingPublicKeys > 0
                  ? // eslint-disable-next-line functional/immutable-data
                    nextState.stack.splice(-requiredApprovingPublicKeys)
                  : [];

              return useOneStackItem(
                nextState,
                // eslint-disable-next-line complexity
                (finalState, [protocolBugValue]) => {
                  if (protocolBugValue.length !== 0) {
                    return applyError(
                      AuthenticationErrorCommon.invalidProtocolBugValue,
                      finalState
                    );
                  }

                  const coveredBytecode = encodeAuthenticationInstructions(
                    finalState.instructions
                  ).subarray(finalState.lastCodeSeparator + 1);

                  let approvingPublicKeys = 0; // eslint-disable-line functional/no-let
                  let remainingSignatures = signatures.length; // eslint-disable-line functional/no-let
                  let remainingPublicKeys = publicKeys.length; // eslint-disable-line functional/no-let
                  // eslint-disable-next-line functional/no-loop-statement
                  while (
                    remainingSignatures > 0 &&
                    remainingPublicKeys > 0 &&
                    approvingPublicKeys + remainingPublicKeys >=
                      remainingSignatures &&
                    approvingPublicKeys !== requiredApprovingPublicKeys
                  ) {
                    const publicKey = publicKeys[remainingPublicKeys - 1];
                    const bitcoinEncodedSignature =
                      signatures[remainingSignatures - 1];

                    if (!isValidPublicKeyEncoding(publicKey)) {
                      return applyError(
                        AuthenticationErrorCommon.invalidPublicKeyEncoding,
                        finalState
                      );
                    }

                    if (
                      !isValidSignatureEncodingBCHTransaction(
                        bitcoinEncodedSignature
                      )
                    ) {
                      return applyError(
                        AuthenticationErrorCommon.invalidSignatureEncoding,
                        finalState
                      );
                    }

                    const { signingSerializationType, signature } =
                      decodeBitcoinSignature(bitcoinEncodedSignature);

                    const serialization = generateSigningSerializationBCH(
                      state.program,
                      { coveredBytecode, signingSerializationType },
                      sha256
                    );
                    const digest = sha256.hash(sha256.hash(serialization));

                    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
                    finalState.signedMessages.push(serialization);

                    if (
                      signature.length ===
                      ConsensusCommon.schnorrSignatureLength
                    ) {
                      return applyError(
                        AuthenticationErrorCommon.schnorrSizedSignatureInCheckMultiSig,
                        finalState
                      );
                    }

                    const signed = secp256k1.verifySignatureDERLowS(
                      signature,
                      publicKey,
                      digest
                    );

                    // eslint-disable-next-line functional/no-conditional-statement
                    if (signed) {
                      approvingPublicKeys += 1; // eslint-disable-line functional/no-expression-statement
                      remainingSignatures -= 1; // eslint-disable-line functional/no-expression-statement
                    }
                    remainingPublicKeys -= 1; // eslint-disable-line functional/no-expression-statement
                  }

                  const success =
                    approvingPublicKeys === requiredApprovingPublicKeys;

                  if (
                    !success &&
                    !signatures.every((signature) => signature.length === 0)
                  ) {
                    return applyError(
                      AuthenticationErrorCommon.nonNullSignatureFailure,
                      finalState
                    );
                  }

                  return pushToStack(finalState, booleanToVmNumber(success));
                }
              );
            }
          );
    });

export const opCheckSigVerify = <
  State extends AuthenticationProgramStateCommon
>(
  {
    secp256k1,
    sha256,
  }: {
    sha256: { hash: Sha256['hash'] };
    secp256k1: {
      verifySignatureSchnorr: Secp256k1['verifySignatureSchnorr'];
      verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
    };
  } = { secp256k1: internalSecp256k1, sha256: internalSha256 }
): Operation<State> =>
  combineOperations(opCheckSig<State>({ secp256k1, sha256 }), opVerify);

export const opCheckMultiSigVerify = <
  State extends AuthenticationProgramStateCommon
>({
  secp256k1,
  sha256,
}: {
  sha256: { hash: Sha256['hash'] };
  secp256k1: {
    verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
  };
}): Operation<State> =>
  combineOperations(opCheckMultiSig<State>({ secp256k1, sha256 }), opVerify);

/**
 * Validate the encoding of a raw signature – a signature without a signing
 * serialization type byte (A.K.A. "sighash" byte).
 *
 * @param signature - the raw signature
 */
export const isValidSignatureEncodingBCHRaw = (signature: Uint8Array) =>
  signature.length === 0 ||
  signature.length === ConsensusCommon.schnorrSignatureLength ||
  isValidSignatureEncodingDER(signature);

export const opCheckDataSig =
  <
    State extends AuthenticationProgramStateError &
      AuthenticationProgramStateSignatureAnalysis &
      AuthenticationProgramStateStack
  >({
    secp256k1,
    sha256,
  }: {
    sha256: { hash: Sha256['hash'] };
    secp256k1: {
      verifySignatureSchnorr: Secp256k1['verifySignatureSchnorr'];
      verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
    };
  }) =>
  (state: State) =>
    // eslint-disable-next-line complexity
    useThreeStackItems(state, (nextState, [signature, message, publicKey]) => {
      if (!isValidSignatureEncodingBCHRaw(signature)) {
        return applyError(
          AuthenticationErrorCommon.invalidSignatureEncoding,
          nextState
        );
      }
      if (!isValidPublicKeyEncoding(publicKey)) {
        return applyError(
          AuthenticationErrorCommon.invalidPublicKeyEncoding,
          nextState
        );
      }
      const digest = sha256.hash(message);

      // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
      nextState.signedMessages.push(message);

      const useSchnorr =
        signature.length === ConsensusCommon.schnorrSignatureLength;
      const success = useSchnorr
        ? secp256k1.verifySignatureSchnorr(signature, publicKey, digest)
        : secp256k1.verifySignatureDERLowS(signature, publicKey, digest);

      return !success && signature.length !== 0
        ? applyError(
            AuthenticationErrorCommon.nonNullSignatureFailure,
            nextState
          )
        : pushToStack(nextState, booleanToVmNumber(success));
    });

export const opCheckDataSigVerify = <
  State extends AuthenticationProgramStateError &
    AuthenticationProgramStateSignatureAnalysis &
    AuthenticationProgramStateStack
>(
  {
    secp256k1,
    sha256,
  }: {
    sha256: { hash: Sha256['hash'] };
    secp256k1: {
      verifySignatureSchnorr: Secp256k1['verifySignatureSchnorr'];
      verifySignatureDERLowS: Secp256k1['verifySignatureDERLowS'];
    };
  } = { secp256k1: internalSecp256k1, sha256: internalSha256 }
) => combineOperations(opCheckDataSig<State>({ secp256k1, sha256 }), opVerify);

export const opReverseBytes = <State extends AuthenticationProgramStateStack>(
  state: State
) =>
  useOneStackItem(state, (nextState, [item]) =>
    pushToStack(nextState, item.slice().reverse())
  );
