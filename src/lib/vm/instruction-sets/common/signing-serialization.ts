import type { CompilationContextBCH } from '../../../lib';
import {
  bigIntToBitcoinVarInt,
  encodeOutpoints,
  encodeOutput,
  encodeOutputsForSigning,
  encodeSequenceNumbersForSigning,
  flattenBinArray,
  numberToBinUint32LE,
} from '../../../lib.js';

/**
 * A.K.A. `sighash` flags
 */
export enum SigningSerializationFlag {
  /**
   * A.K.A. `SIGHASH_ALL`
   */
  allOutputs = 0x01,
  /**
   * A.K.A `SIGHASH_NONE`
   */
  noOutputs = 0x02,
  /**
   * A.K.A. `SIGHASH_SINGLE`
   */
  correspondingOutput = 0x03,
  forkId = 0x40,
  /**
   * A.K.A `ANYONE_CAN_PAY`
   */
  singleInput = 0x80,
}

const enum Internal {
  mask5Bits = 0b11111,
  sha256HashByteLength = 32,
}

export const isDefinedSigningSerializationType = (byte: number) => {
  const baseType =
    // eslint-disable-next-line no-bitwise
    byte &
    // eslint-disable-next-line no-bitwise
    ~(SigningSerializationFlag.forkId | SigningSerializationFlag.singleInput);
  return (
    baseType >= SigningSerializationFlag.allOutputs &&
    baseType <= SigningSerializationFlag.correspondingOutput
  );
};

const match = (type: Uint8Array, flag: SigningSerializationFlag) =>
  // eslint-disable-next-line no-bitwise
  (type[0] & flag) !== 0;

const equals = (
  type: Uint8Array,
  flag: SigningSerializationFlag
  // eslint-disable-next-line no-bitwise
) => (type[0] & Internal.mask5Bits) === flag;

const shouldSerializeSingleInput = (type: Uint8Array) =>
  match(type, SigningSerializationFlag.singleInput);

const shouldSerializeCorrespondingOutput = (type: Uint8Array) =>
  equals(type, SigningSerializationFlag.correspondingOutput);

const shouldSerializeNoOutputs = (type: Uint8Array) =>
  equals(type, SigningSerializationFlag.noOutputs);

const emptyHash = () => new Uint8Array(Internal.sha256HashByteLength).fill(0);

/**
 * Return the proper `hashPrevouts` value for a given a signing serialization
 * type.
 * @param signingSerializationType - the signing serialization type to test
 * @param transactionOutpoints - see `generateSigningSerializationBCH`
 */
export const hashPrevouts = ({
  sha256,
  signingSerializationType,
  transactionOutpoints,
}: {
  sha256: { hash: (input: Uint8Array) => Uint8Array };
  signingSerializationType: Uint8Array;
  transactionOutpoints: Uint8Array;
}) =>
  shouldSerializeSingleInput(signingSerializationType)
    ? emptyHash()
    : sha256.hash(sha256.hash(transactionOutpoints));

/**
 * Return the proper `hashSequence` value for a given a signing serialization
 * type.
 * @param signingSerializationType - the signing serialization type to test
 * @param transactionSequenceNumbers - see
 * `generateSigningSerializationBCH`
 */
export const hashSequence = ({
  sha256,
  signingSerializationType,
  transactionSequenceNumbers,
}: {
  sha256: { hash: (input: Uint8Array) => Uint8Array };
  signingSerializationType: Uint8Array;
  transactionSequenceNumbers: Uint8Array;
}) =>
  !shouldSerializeSingleInput(signingSerializationType) &&
  !shouldSerializeCorrespondingOutput(signingSerializationType) &&
  !shouldSerializeNoOutputs(signingSerializationType)
    ? sha256.hash(sha256.hash(transactionSequenceNumbers))
    : emptyHash();

/**
 * Return the proper `hashOutputs` value for a given a signing serialization
 * type.
 * @param signingSerializationType - the signing serialization type to test
 * @param transactionOutputs - see `generateSigningSerializationBCH`
 * @param correspondingOutput - see `generateSigningSerializationBCH`
 */
export const hashOutputs = ({
  correspondingOutput,
  sha256,
  signingSerializationType,
  transactionOutputs,
}: {
  sha256: { hash: (input: Uint8Array) => Uint8Array };
  signingSerializationType: Uint8Array;
  transactionOutputs: Uint8Array;
  correspondingOutput: Uint8Array | undefined;
}) =>
  !shouldSerializeCorrespondingOutput(signingSerializationType) &&
  !shouldSerializeNoOutputs(signingSerializationType)
    ? sha256.hash(sha256.hash(transactionOutputs))
    : shouldSerializeCorrespondingOutput(signingSerializationType)
    ? correspondingOutput === undefined
      ? emptyHash()
      : sha256.hash(sha256.hash(correspondingOutput))
    : emptyHash();

/**
 * Encode the signature-protected properties of a transaction following the
 * algorithm required by the `signingSerializationType` of a signature.
 *
 * Note: When validating transactions with multiple signatures,
 * performance-critical applications should use a memoized sha256 implementation
 * to avoid re-computing hashes.
 */
export const encodeSigningSerializationBCH = (
  sha256: { hash: (input: Uint8Array) => Uint8Array },
  {
    correspondingOutput,
    coveredBytecode,
    forkId = new Uint8Array([0, 0, 0]),
    locktime,
    outpointIndex,
    outpointTransactionHash,
    outputValue,
    sequenceNumber,
    signingSerializationType,
    transactionOutpoints,
    transactionOutputs,
    transactionSequenceNumbers,
    version,
  }: {
    /**
     * The version number of the transaction.
     */
    version: number;
    /**
     * The serialization of all input outpoints (A.K.A. `hashPrevouts`) – used if
     * `ANYONECANPAY` is not set.
     */
    transactionOutpoints: Uint8Array;
    /**
     * The serialization of all input sequence numbers. (A.K.A. `hashSequence`) –
     * used if none of `ANYONECANPAY`, `SINGLE`, or `NONE` are set.
     */
    transactionSequenceNumbers: Uint8Array;
    /**
     * The big-endian (standard) transaction hash of the outpoint being spent.
     */
    outpointTransactionHash: Uint8Array;
    /**
     * The index of the outpoint being spent in `outpointTransactionHash`.
     */
    outpointIndex: number;
    /**
     * The encoded script currently being executed, beginning at the
     * `lastCodeSeparator`.
     */
    coveredBytecode: Uint8Array;
    /**
     * The 8-byte `Uint64LE`-encoded value of the outpoint in satoshis (see
     * `bigIntToBinUint64LE`).
     */
    outputValue: Uint8Array;
    /**
     * The sequence number of the input (A.K.A. `nSequence`).
     */
    sequenceNumber: number;
    /**
     * The serialization of the output at the same index as this input (A.K.A.
     * `hashOutputs` with `SIGHASH_SINGLE`) – only used if `SINGLE` is set.
     */
    correspondingOutput: Uint8Array | undefined;
    /**
     * The serialization of output amounts and locking bytecode values (A.K.A.
     * `hashOutputs` with `SIGHASH_ALL`) – only used if `ALL` is set.
     */
    transactionOutputs: Uint8Array;
    /**
     * The locktime of the transaction.
     */
    locktime: number;
    /**
     * The signing serialization type of the signature (A.K.A. `sighash` type).
     */
    signingSerializationType: Uint8Array;
    /**
     * While a bitcoin-encoded signature only includes a single byte to encode the
     * signing serialization type, a 3-byte forkId can be appended to provide
     * replay-protection between different forks. (See Bitcoin Cash's Replay
     * Protected Sighash spec for details.)
     */
    forkId?: Uint8Array;
  }
) =>
  flattenBinArray([
    numberToBinUint32LE(version),
    hashPrevouts({ sha256, signingSerializationType, transactionOutpoints }),
    hashSequence({
      sha256,
      signingSerializationType,
      transactionSequenceNumbers,
    }),
    outpointTransactionHash.slice().reverse(),
    numberToBinUint32LE(outpointIndex),
    bigIntToBitcoinVarInt(BigInt(coveredBytecode.length)),
    coveredBytecode,
    outputValue,
    numberToBinUint32LE(sequenceNumber),
    hashOutputs({
      correspondingOutput,
      sha256,
      signingSerializationType,
      transactionOutputs,
    }),
    numberToBinUint32LE(locktime),
    signingSerializationType,
    forkId,
  ]);

/**
 * The signing serialization components which are shared between all of the
 * inputs in a transaction.
 */
export interface SigningSerializationTransactionComponentsBCH {
  /**
   * A time or block height at which the transaction is considered valid (and
   * can be added to the block chain). This allows signers to create time-locked
   * transactions which may only become valid in the future.
   */
  readonly locktime: number;
  /**
   * A.K.A. the serialization for `hashPrevouts`
   *
   * The signing serialization of all input outpoints. (See BIP143 or Bitcoin
   * Cash's Replay Protected Sighash spec for details.)
   */
  readonly transactionOutpoints: Uint8Array;
  /*
   * A.K.A. the serialization for `hashOutputs` with `SIGHASH_ALL`
   *
   * The signing serialization of output amounts and locking scripts. (See
   * BIP143 or Bitcoin Cash's Replay Protected Sighash spec for details.)
   */
  readonly transactionOutputs: Uint8Array;
  /*
   * A.K.A. the serialization for `hashSequence`
   *
   * The signing serialization of all input sequence numbers. (See BIP143 or
   * Bitcoin Cash's Replay Protected Sighash spec for details.)
   */
  readonly transactionSequenceNumbers: Uint8Array;
  readonly version: number;
}

/**
 * All signing serialization components for a particular transaction input.
 */
export interface SigningSerializationComponentsBCH
  extends SigningSerializationTransactionComponentsBCH {
  /*
   * A.K.A. the serialization for `hashOutputs` with `SIGHASH_SINGLE`
   *
   * The signing serialization of the output at the same index as this input. If
   * this input's index is larger than the total number of outputs (such that
   * there is no corresponding output), this should be `undefined`. (See BIP143
   * or Bitcoin Cash's Replay Protected Sighash spec for details.)
   */
  readonly correspondingOutput: Uint8Array | undefined;
  /**
   * The index (within the previous transaction) of the outpoint being spent by
   * this input.
   */
  readonly outpointIndex: number;
  /**
   * The hash/ID of the transaction from which the outpoint being spent by this
   * input originated.
   */
  readonly outpointTransactionHash: Uint8Array;
  /**
   * The 8-byte `Uint64LE`-encoded value of the outpoint in satoshis (see
   * `bigIntToBinUint64LE`).
   */
  readonly outputValue: Uint8Array;
  /**
   * The `sequenceNumber` associated with the input being validated. See
   * `Input.sequenceNumber` for details.
   */
  readonly sequenceNumber: number;
}

/**
 * Generate the encoded components of a BCH signing serialization from
 * compilation context.
 */
export const generateSigningSerializationComponentsBCH = (
  context: CompilationContextBCH
): SigningSerializationComponentsBCH => ({
  correspondingOutput:
    context.inputIndex < context.transaction.outputs.length
      ? encodeOutput(context.transaction.outputs[context.inputIndex])
      : undefined,
  locktime: context.transaction.locktime,
  outpointIndex: context.transaction.inputs[context.inputIndex].outpointIndex,
  outpointTransactionHash:
    context.transaction.inputs[context.inputIndex].outpointTransactionHash,
  outputValue: context.sourceOutputs[context.inputIndex].valueSatoshis,
  sequenceNumber: context.transaction.inputs[context.inputIndex].sequenceNumber,
  transactionOutpoints: encodeOutpoints(context.transaction.inputs),
  transactionOutputs: encodeOutputsForSigning(context.transaction.outputs),
  transactionSequenceNumbers: encodeSequenceNumbersForSigning(
    context.transaction.inputs
  ),
  version: context.transaction.version,
});

/**
 * Generate the signing serialization for a particular transaction input
 * following the algorithm required by the provided `signingSerializationType`.
 *
 * Note: When validating transactions with multiple signatures,
 * performance-critical applications should use a memoized sha256 implementation
 * to avoid re-computing hashes.
 */
export const generateSigningSerializationBCH = (
  sha256: { hash: (input: Uint8Array) => Uint8Array },
  context: CompilationContextBCH,
  {
    coveredBytecode,
    signingSerializationType,
  }: {
    /**
     * The encoded script currently being executed, beginning at the
     * `lastCodeSeparator`.
     */
    coveredBytecode: Uint8Array;
    /**
     * The signing serialization type of the signature (A.K.A. `sighash` type).
     */
    signingSerializationType: Uint8Array;
  }
) =>
  encodeSigningSerializationBCH(sha256, {
    ...generateSigningSerializationComponentsBCH(context),
    coveredBytecode,
    signingSerializationType,
  });

/**
 * @param signingSerializationType - the 32-bit number indicating the signing
 * serialization algorithm to use
 */
export const isLegacySigningSerialization = (
  signingSerializationType: number
) => {
  // eslint-disable-next-line no-bitwise, @typescript-eslint/no-magic-numbers
  const forkValue = signingSerializationType >> 8;
  // eslint-disable-next-line no-bitwise, @typescript-eslint/no-magic-numbers
  const newForkValue = (forkValue ^ 0xdead) | 0xff0000;
  // eslint-disable-next-line no-bitwise, @typescript-eslint/no-magic-numbers
  const sighashType = (newForkValue << 8) | (signingSerializationType & 0xff);
  // eslint-disable-next-line no-bitwise
  return (sighashType & SigningSerializationFlag.forkId) === 0;
};
