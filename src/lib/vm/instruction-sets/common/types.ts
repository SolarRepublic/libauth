import type { AuthenticationInstruction } from '../../../lib';
import { Opcodes } from '../../../lib.js';

export enum VmNumberError {
  outOfRange = 'Failed to decode VM Number: overflows VM Number range.',
  requiresMinimal = 'Failed to decode VM Number: the number is not minimally-encoded.',
}

export const isVmNumberError = (
  value: BigInt | VmNumberError
): value is VmNumberError =>
  value === VmNumberError.outOfRange || value === VmNumberError.requiresMinimal;

const typicalMaximumVmNumberByteLength = 8;

/**
 * This method attempts to decode a VM Number, a format in which numeric values
 * are represented on the stack. (The Satoshi implementation calls this
 * `CScriptNum`.)
 *
 * If `bytes` is a valid VM Number, this method returns the represented number
 * in BigInt format. If `bytes` is not valid, a {@link VmNumberError}
 * is returned.
 *
 * All common operations accepting numeric parameters or pushing numeric values
 * to the stack currently use the VM Number format. The binary format of numbers
 * wouldn't be important if they could only be operated on by arithmetic
 * operators, but since the results of these operations may become input to
 * other operations (e.g. hashing), the specific representation is consensus-
 * critical.
 *
 * @param bytes - a Uint8Array from the stack
 */
// eslint-disable-next-line complexity
export const decodeVmNumber = (
  bytes: Uint8Array,
  {
    maximumVmNumberByteLength = typicalMaximumVmNumberByteLength,
    requireMinimalEncoding = true,
  }: {
    /**
     * The maximum valid number of bytes in a VM Number.
     */
    maximumVmNumberByteLength?: number;
    /**
     * If `true`, this method returns an error when parsing non-minimally
     * encoded VM Numbers.
     */
    requireMinimalEncoding?: boolean;
  } = {
    maximumVmNumberByteLength: typicalMaximumVmNumberByteLength,
    requireMinimalEncoding: true,
  }
): VmNumberError | bigint => {
  if (bytes.length === 0) {
    return BigInt(0);
  }
  if (bytes.length > maximumVmNumberByteLength) {
    return VmNumberError.outOfRange;
  }
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const mostSignificantByte = bytes[bytes.length - 1]!;
  const secondMostSignificantByte = bytes[bytes.length - 1 - 1];
  const allButTheSignBit = 0b1111_111;
  const justTheSignBit = 0b1000_0000;

  if (
    requireMinimalEncoding &&
    // eslint-disable-next-line no-bitwise
    (mostSignificantByte & allButTheSignBit) === 0 &&
    // eslint-disable-next-line no-bitwise, @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-unnecessary-type-assertion
    (bytes.length <= 1 || (secondMostSignificantByte! & justTheSignBit) === 0)
  ) {
    return VmNumberError.requiresMinimal;
  }

  const bitsPerByte = 8;
  const signFlippingByte = 0x80;
  // eslint-disable-next-line functional/no-let
  let result = BigInt(0);
  // eslint-disable-next-line functional/no-let, functional/no-loop-statement, no-plusplus
  for (let byte = 0; byte < bytes.length; byte++) {
    // eslint-disable-next-line functional/no-expression-statement,  no-bitwise, @typescript-eslint/no-non-null-assertion
    result |= BigInt(bytes[byte]!) << BigInt(byte * bitsPerByte);
  }

  /* eslint-disable no-bitwise */
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const isNegative = (bytes[bytes.length - 1]! & signFlippingByte) !== 0;
  return isNegative
    ? -(
        result &
        ~(BigInt(signFlippingByte) << BigInt(bitsPerByte * (bytes.length - 1)))
      )
    : result;
  /* eslint-enable no-bitwise */
};

/**
 * Convert a BigInt into the VM Number format. See {@link decodeVmNumber} for
 * more information.
 *
 * @param integer - the BigInt to encode as a VM Number
 */
// eslint-disable-next-line complexity
export const bigIntToVmNumber = (integer: bigint): Uint8Array => {
  if (integer === BigInt(0)) {
    return new Uint8Array();
  }

  const bytes: number[] = [];
  const isNegative = integer < 0;
  const byteStates = 0xff;
  const bitsPerByte = 8;
  // eslint-disable-next-line functional/no-let
  let remaining = isNegative ? -integer : integer;
  // eslint-disable-next-line functional/no-loop-statement
  while (remaining > 0) {
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data, no-bitwise
    bytes.push(Number(remaining & BigInt(byteStates)));
    // eslint-disable-next-line functional/no-expression-statement, no-bitwise
    remaining >>= BigInt(bitsPerByte);
  }

  const signFlippingByte = 0x80;
  // eslint-disable-next-line no-bitwise, functional/no-conditional-statement, @typescript-eslint/no-non-null-assertion
  if ((bytes[bytes.length - 1]! & signFlippingByte) > 0) {
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    bytes.push(isNegative ? signFlippingByte : 0x00);
    // eslint-disable-next-line functional/no-conditional-statement
  } else if (isNegative) {
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data, no-bitwise
    bytes[bytes.length - 1] |= signFlippingByte;
  }
  return new Uint8Array(bytes);
};

/**
 * Returns true if the provided stack item is "truthy" in the sense required
 * by several operations (anything but zero and "negative zero").
 *
 * The Satoshi implementation calls this method `CastToBool`.
 *
 * @param item - the stack item to check for truthiness
 */
export const stackItemIsTruthy = (item: Uint8Array) => {
  const signFlippingByte = 0x80;
  // eslint-disable-next-line functional/no-let, functional/no-loop-statement, no-plusplus
  for (let i = 0; i < item.length; i++) {
    if (item[i] !== 0) {
      if (i === item.length - 1 && item[i] === signFlippingByte) {
        return false;
      }
      return true;
    }
  }
  return false;
};

/**
 * Convert a boolean into VM Number format (the type used to express
 * boolean values emitted by several operations).
 *
 * @param value - the boolean value to convert
 */
export const booleanToVmNumber = (value: boolean) =>
  value ? bigIntToVmNumber(BigInt(1)) : bigIntToVmNumber(BigInt(0));

const enum PayToScriptHash {
  length = 3,
  lastElement = 2,
}

export const isPayToScriptHash = (
  verificationInstructions: readonly AuthenticationInstruction[]
) =>
  verificationInstructions.length === PayToScriptHash.length &&
  verificationInstructions[0]?.opcode === Opcodes.OP_HASH160 &&
  verificationInstructions[1]?.opcode === Opcodes.OP_PUSHBYTES_20 &&
  verificationInstructions[PayToScriptHash.lastElement]?.opcode ===
    Opcodes.OP_EQUAL;

const enum SegWit {
  minimumLength = 4,
  maximumLength = 42,
  OP_0 = 0,
  OP_1 = 81,
  OP_16 = 96,
  versionAndLengthBytes = 2,
}

/**
 * Test a stack item for the SegWit Recovery Rules activated in `BCH_2019_05`.
 *
 * @param bytecode - the stack item to test
 */
// eslint-disable-next-line complexity
export const isWitnessProgram = (bytecode: Uint8Array) => {
  const correctLength =
    bytecode.length >= SegWit.minimumLength &&
    bytecode.length <= SegWit.maximumLength;
  const validVersionPush =
    bytecode[0] === SegWit.OP_0 ||
    (bytecode[0] >= SegWit.OP_1 && bytecode[0] <= SegWit.OP_16);
  const correctLengthByte =
    bytecode[1] + SegWit.versionAndLengthBytes === bytecode.length;
  return correctLength && validVersionPush && correctLengthByte;
};

/**
 * From C++ implementation:
 * Note that IsPushOnly() *does* consider OP_RESERVED to be a push-type
 * opcode, however execution of OP_RESERVED fails, so it's not relevant to
 * P2SH/BIP62 as the scriptSig would fail prior to the P2SH special
 * validation code being executed.
 */
export const isPushOperation = (opcode: number) => opcode <= Opcodes.OP_16;
