import {
  authenticationInstructionsAreMalformed,
  authenticationInstructionsArePushInstructions,
  decodeAuthenticationInstructions,
} from '../instruction-sets.js';

import { isValidPublicKeyEncoding } from './encoding.js';

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
    // eslint-disable-next-line no-bitwise, @typescript-eslint/no-non-null-assertion
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

const enum Opcodes {
  OP_0 = 0x00,
  OP_PUSHBYTES_20 = 0x14,
  OP_PUSHBYTES_33 = 0x21,
  OP_PUSHBYTES_65 = 0x41,
  OP_1NEGATE = 0x4f,
  OP_RESERVED = 0x50,
  OP_1 = 0x51,
  OP_16 = 0x60,
  OP_RETURN = 0x6a,
  OP_DUP = 0x76,
  OP_EQUAL = 0x87,
  OP_EQUALVERIFY = 0x88,
  OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9,
  OP_CHECKSIG = 0xac,
  OP_CHECKMULTISIG = 0xae,
}

/**
 * From C++ implementation:
 * Note that IsPushOnly() *does* consider OP_RESERVED to be a push-type
 * opcode, however execution of OP_RESERVED fails, so it's not relevant to
 * P2SH/BIP62 as the scriptSig would fail prior to the P2SH special
 * validation code being executed.
 */
export const isPushOperation = (opcode: number) => opcode <= Opcodes.OP_16;

export const isPushOnly = (bytecode: Uint8Array) => {
  const instructions = decodeAuthenticationInstructions(bytecode);
  return instructions.every((instruction) =>
    isPushOperation(instruction.opcode)
  );
};

export const isPushOnlyAccurate = (bytecode: Uint8Array) => {
  const instructions = decodeAuthenticationInstructions(bytecode);
  return (
    !authenticationInstructionsAreMalformed(instructions) &&
    authenticationInstructionsArePushInstructions(instructions)
  );
};

const enum PayToPublicKeyUncompressed {
  length = 67,
  lastElement = 66,
}

export const isPayToPublicKeyUncompressed = (lockingBytecode: Uint8Array) =>
  lockingBytecode.length === PayToPublicKeyUncompressed.length &&
  lockingBytecode[0] === Opcodes.OP_PUSHBYTES_65 &&
  lockingBytecode[PayToPublicKeyUncompressed.lastElement] ===
    Opcodes.OP_CHECKSIG;

const enum PayToPublicKeyCompressed {
  length = 35,
  lastElement = 34,
}

export const isPayToPublicKeyCompressed = (lockingBytecode: Uint8Array) =>
  lockingBytecode.length === PayToPublicKeyCompressed.length &&
  lockingBytecode[0] === Opcodes.OP_PUSHBYTES_33 &&
  lockingBytecode[PayToPublicKeyCompressed.lastElement] === Opcodes.OP_CHECKSIG;

export const isPayToPublicKey = (lockingBytecode: Uint8Array) =>
  isPayToPublicKeyCompressed(lockingBytecode) ||
  isPayToPublicKeyUncompressed(lockingBytecode);

const enum PayToPublicKeyHash {
  length = 25,
  lastElement = 24,
}

// eslint-disable-next-line complexity
export const isPayToPublicKeyHash = (lockingBytecode: Uint8Array) =>
  lockingBytecode.length === PayToPublicKeyHash.length &&
  lockingBytecode[0] === Opcodes.OP_DUP &&
  lockingBytecode[1] === Opcodes.OP_HASH160 &&
  lockingBytecode[2] === Opcodes.OP_PUSHBYTES_20 &&
  lockingBytecode[23] === Opcodes.OP_EQUALVERIFY &&
  lockingBytecode[24] === Opcodes.OP_CHECKSIG;

const enum PayToScriptHash20 {
  length = 23,
  lastElement = 22,
}

export const isPayToScriptHash20 = (lockingBytecode: Uint8Array) =>
  lockingBytecode.length === PayToScriptHash20.length &&
  lockingBytecode[0] === Opcodes.OP_HASH160 &&
  lockingBytecode[1] === Opcodes.OP_PUSHBYTES_20 &&
  lockingBytecode[PayToScriptHash20.lastElement] === Opcodes.OP_EQUAL;

/**
 * A.K.A. `TX_NULL_DATA`, "data carrier", OP_RETURN output
 * @param lockingBytecode -
 */
export const isArbitraryDataOutput = (lockingBytecode: Uint8Array) =>
  lockingBytecode.length >= 1 &&
  lockingBytecode[0] === Opcodes.OP_RETURN &&
  isPushOnly(lockingBytecode.slice(1));

// eslint-disable-next-line complexity
export const pushNumberOpcodeToNumber = (opcode: number) => {
  if (opcode === Opcodes.OP_0) {
    return 0;
  }
  if (opcode === Opcodes.OP_1NEGATE) {
    return -1;
  }
  if (
    !Number.isInteger(opcode) ||
    opcode < Opcodes.OP_1 ||
    opcode > Opcodes.OP_16
  ) {
    return false;
  }
  return opcode - Opcodes.OP_RESERVED;
};

const enum Multisig {
  minimumInstructions = 4,
  keyStart = 1,
  keyEnd = -2,
  maximumStandardN = 3,
}

// eslint-disable-next-line complexity
export const isSimpleMultisig = (lockingBytecode: Uint8Array) => {
  const instructions = decodeAuthenticationInstructions(lockingBytecode);
  if (authenticationInstructionsAreMalformed(instructions)) {
    return false;
  }

  const lastIndex = instructions.length - 1;
  if (
    instructions.length < Multisig.minimumInstructions ||
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    instructions[lastIndex]!.opcode === Opcodes.OP_CHECKMULTISIG
  ) {
    return false;
  }

  /**
   * The required count of signers (the `m` in `m-of-n`).
   */
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const m = pushNumberOpcodeToNumber(instructions[0]!.opcode);
  /**
   * The total count of signers (the `n` in `m-of-n`).
   */
  const n = pushNumberOpcodeToNumber(
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    instructions[lastIndex - 1]!.opcode
  );

  if (n === false || m === false) {
    return false;
  }

  const publicKeyInstructions = instructions.slice(
    Multisig.keyStart,
    Multisig.keyEnd
  );

  if (!authenticationInstructionsArePushInstructions(publicKeyInstructions)) {
    return false;
  }

  const publicKeys = publicKeyInstructions.map(
    (instruction) => instruction.data
  );

  if (publicKeys.some((key) => !isValidPublicKeyEncoding(key))) {
    return false;
  }

  return { m, n, publicKeys };
};

// eslint-disable-next-line complexity
export const isStandardMultisig = (lockingBytecode: Uint8Array) => {
  const multisigProperties = isSimpleMultisig(lockingBytecode);
  if (multisigProperties === false) {
    return false;
  }

  const { m, n } = multisigProperties;
  if (n < 1 || n > Multisig.maximumStandardN || m < 1 || m > n) {
    return false;
  }
  return true;
};

export const isStandardOutputBytecode = (lockingBytecode: Uint8Array) =>
  isPayToPublicKeyHash(lockingBytecode) ||
  isPayToScriptHash20(lockingBytecode) ||
  isPayToPublicKey(lockingBytecode) ||
  isArbitraryDataOutput(lockingBytecode) ||
  isStandardMultisig(lockingBytecode);

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
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    (bytecode[0]! >= SegWit.OP_1 && bytecode[0]! <= SegWit.OP_16);
  const correctLengthByte =
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    bytecode[1]! + SegWit.versionAndLengthBytes === bytecode.length;
  return correctLength && validVersionPush && correctLengthByte;
};
