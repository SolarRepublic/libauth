import {
  binToHex,
  createCompilerCommonSynchronous,
  flattenBinArray,
  numberToBinUint16LE,
  numberToBinUint32LE,
} from '../../lib.js';
import type { AuthenticationProgramStateCommon } from '../vm';

import type {
  AuthenticationInstruction,
  AuthenticationInstructionPush,
  ParsedAuthenticationInstruction,
  ParsedAuthenticationInstructionMalformed,
  ParsedAuthenticationInstructionPushMalformedLength,
  ParsedAuthenticationInstructions,
} from './instruction-sets';
import { OpcodesBCH2022, OpcodesBTC } from './instruction-sets.js';

/**
 * A type-guard which checks if the provided instruction is malformed.
 * @param instruction - the instruction to check
 */
export const authenticationInstructionIsMalformed = (
  instruction: ParsedAuthenticationInstruction
): instruction is ParsedAuthenticationInstructionMalformed =>
  'malformed' in instruction;

/**
 * A type-guard which checks if the final instruction in the provided array of
 * instructions is malformed. (Only the final instruction can be malformed.)
 * @param instruction - the array of instructions to check
 */
export const authenticationInstructionsAreMalformed = (
  instructions: ParsedAuthenticationInstructions
): instructions is [
  ...AuthenticationInstruction[],
  ParsedAuthenticationInstructionMalformed
] =>
  instructions.length > 0 &&
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  authenticationInstructionIsMalformed(instructions[instructions.length - 1]!);

/**
 * A type-guard which confirms that the final instruction in the provided array
 * is not malformed. (Only the final instruction can be malformed.)
 * @param instruction - the array of instructions to check
 */
export const authenticationInstructionsAreNotMalformed = (
  instructions: ParsedAuthenticationInstructions
): instructions is [
  ...AuthenticationInstruction[],
  AuthenticationInstruction
] => !authenticationInstructionsAreMalformed(instructions);

enum CommonPushOpcodes {
  OP_0 = 0x00,
  OP_PUSHDATA_1 = 0x4c,
  OP_PUSHDATA_2 = 0x4d,
  OP_PUSHDATA_4 = 0x4e,
}

const uint8Bytes = 1;
const uint16Bytes = 2;
const uint32Bytes = 4;

const readLittleEndianNumber = (
  script: Uint8Array,
  index: number,
  length: typeof uint8Bytes | typeof uint16Bytes | typeof uint32Bytes
) => {
  const view = new DataView(script.buffer, index, length);
  const readAsLittleEndian = true;
  return length === uint8Bytes
    ? view.getUint8(0)
    : length === uint16Bytes
    ? view.getUint16(0, readAsLittleEndian)
    : view.getUint32(0, readAsLittleEndian);
};

/**
 * Returns the number of bytes used to indicate the length of the push in this
 * operation.
 * @param opcode - an opcode between 0x00 and 0x4e
 */
export const lengthBytesForPushOpcode = (opcode: number) =>
  opcode < CommonPushOpcodes.OP_PUSHDATA_1
    ? 0
    : opcode === CommonPushOpcodes.OP_PUSHDATA_1
    ? uint8Bytes
    : opcode === CommonPushOpcodes.OP_PUSHDATA_2
    ? uint16Bytes
    : uint32Bytes;

/**
 * Parse one instruction from the provided script.
 *
 * Returns an object with an `instruction` referencing a
 * `ParsedAuthenticationInstruction`, and a `nextIndex` indicating the next
 * index from which to read. If the next index is greater than or equal to the
 * length of the script, the script has been fully parsed.
 *
 * The final `ParsedAuthenticationInstruction` from an encoded script may be
 * malformed if 1) the final operation is a push and 2) too few bytes remain for
 * the push operation to complete.
 *
 * @param script - the script from which to read the next instruction
 * @param index - the offset from which to begin reading
 */
// eslint-disable-next-line complexity
export const readAuthenticationInstruction = (
  script: Uint8Array,
  index: number
): {
  instruction: ParsedAuthenticationInstruction;
  nextIndex: number;
} => {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const opcode = script[index]!;
  if (opcode > CommonPushOpcodes.OP_PUSHDATA_4) {
    return {
      instruction: {
        opcode,
      },
      nextIndex: index + 1,
    };
  }
  const lengthBytes = lengthBytesForPushOpcode(opcode);

  if (lengthBytes !== 0 && index + lengthBytes >= script.length) {
    const sliceStart = index + 1;
    const sliceEnd = sliceStart + lengthBytes;
    return {
      instruction: {
        expectedLengthBytes: lengthBytes,
        length: script.slice(sliceStart, sliceEnd),
        malformed: true,
        opcode,
      },
      nextIndex: sliceEnd,
    };
  }

  const dataBytes =
    lengthBytes === 0
      ? opcode
      : readLittleEndianNumber(script, index + 1, lengthBytes);
  const dataStart = index + 1 + lengthBytes;
  const dataEnd = dataStart + dataBytes;
  return {
    instruction: {
      data: script.slice(dataStart, dataEnd),
      ...(dataEnd > script.length
        ? {
            expectedDataBytes: dataEnd - dataStart,
            malformed: true,
          }
        : undefined),
      opcode,
    },
    nextIndex: dataEnd,
  };
};

/**
 * @param instruction - the AuthenticationInstruction to clone.
 * @returns A copy of the provided AuthenticationInstruction.
 */
export const cloneAuthenticationInstruction = (
  instruction: Readonly<AuthenticationInstruction>
): AuthenticationInstruction => ({
  ...('data' in instruction ? { data: instruction.data } : {}),
  opcode: instruction.opcode,
});

/**
 * Parse authentication bytecode (`lockingBytecode` or `unlockingBytecode`)
 * into `ParsedAuthenticationInstructions`. The method
 * `authenticationInstructionsAreMalformed` can be used to check if these
 * instructions include a malformed instruction. If not, they are valid
 * `AuthenticationInstructions`.
 *
 * @param script - the encoded script to parse
 */
export const parseBytecode = (script: Uint8Array) => {
  const instructions: ParsedAuthenticationInstructions = [];
  // eslint-disable-next-line functional/no-let
  let i = 0;
  // eslint-disable-next-line functional/no-loop-statement
  while (i < script.length) {
    const { instruction, nextIndex } = readAuthenticationInstruction(script, i);
    // eslint-disable-next-line functional/no-expression-statement
    i = nextIndex;
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    (instructions as AuthenticationInstruction[]).push(instruction);
  }
  return instructions as ParsedAuthenticationInstructions;
};

/**
 * OP_0 is the only single-word push. All other push instructions will
 * disassemble to multiple ASM words. (OP_1-OP_16 are handled like normal
 * operations.)
 */
const isMultiWordPush = (opcode: number) => opcode !== CommonPushOpcodes.OP_0;
const formatAsmPushHex = (data: Uint8Array) =>
  data.length > 0 ? `0x${binToHex(data)}` : '';
const formatMissingBytesAsm = (missing: number) =>
  `[missing ${missing} byte${missing === 1 ? '' : 's'}]`;
const hasMalformedLength = (
  instruction: ParsedAuthenticationInstructionMalformed
): instruction is ParsedAuthenticationInstructionPushMalformedLength =>
  'length' in instruction;
const isPushData = (pushOpcode: number) =>
  pushOpcode >= CommonPushOpcodes.OP_PUSHDATA_1;

/**
 * Disassemble a malformed authentication instruction into a string description.
 * @param opcodes - a mapping of possible opcodes to their string representation
 * @param instruction - the malformed instruction to disassemble
 */
export const disassembleParsedAuthenticationInstructionMalformed = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instruction: ParsedAuthenticationInstructionMalformed
): string =>
  `${opcodes[instruction.opcode]} ${
    hasMalformedLength(instruction)
      ? `${formatAsmPushHex(instruction.length)}${formatMissingBytesAsm(
          instruction.expectedLengthBytes - instruction.length.length
        )}`
      : `${
          isPushData(instruction.opcode)
            ? `${instruction.expectedDataBytes} `
            : ''
        }${formatAsmPushHex(instruction.data)}${formatMissingBytesAsm(
          instruction.expectedDataBytes - instruction.data.length
        )}`
  }`;

/**
 * Disassemble a properly-formed authentication instruction into a string
 * description.
 * @param opcodes - a mapping of possible opcodes to their string representation
 * @param instruction - the instruction to disassemble
 */
export const disassembleAuthenticationInstruction = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instruction: AuthenticationInstruction
): string =>
  `${opcodes[instruction.opcode]}${
    'data' in instruction && isMultiWordPush(instruction.opcode)
      ? ` ${
          isPushData(instruction.opcode) ? `${instruction.data.length} ` : ''
        }${formatAsmPushHex(instruction.data)}`
      : ''
  }`;

/**
 * Disassemble a single `ParsedAuthenticationInstruction` (includes potentially
 * malformed instructions) into its ASM representation.
 *
 * @param script - the instruction to disassemble
 */
export const disassembleParsedAuthenticationInstruction = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instruction: ParsedAuthenticationInstruction
): string =>
  authenticationInstructionIsMalformed(instruction)
    ? disassembleParsedAuthenticationInstructionMalformed(opcodes, instruction)
    : disassembleAuthenticationInstruction(opcodes, instruction);

/**
 * Disassemble an array of `ParsedAuthenticationInstructions` (including
 * potentially malformed instructions) into its ASM representation.
 *
 * @param script - the array of instructions to disassemble
 */
export const disassembleParsedAuthenticationInstructions = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instructions: readonly ParsedAuthenticationInstruction[]
): string =>
  instructions
    .map((instruction) =>
      disassembleParsedAuthenticationInstruction(opcodes, instruction)
    )
    .join(' ');

/**
 * Disassemble authentication bytecode into a lossless ASM representation. (All
 * push operations are represented with the same opcodes used in the bytecode,
 * even when non-minimally encoded.)
 *
 * @param opcodes - the set to use when determining the name of opcodes, e.g. `OpcodesBCH`
 * @param bytecode - the authentication bytecode to disassemble
 */
export const disassembleBytecode = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  bytecode: Uint8Array
) =>
  disassembleParsedAuthenticationInstructions(opcodes, parseBytecode(bytecode));

/**
 * Disassemble BCH authentication bytecode into its ASM representation.
 * @param bytecode - the authentication bytecode to disassemble
 */
export const disassembleBytecodeBCH = (bytecode: Uint8Array) =>
  disassembleParsedAuthenticationInstructions(
    OpcodesBCH2022,
    parseBytecode(bytecode)
  );

/**
 * Disassemble BTC authentication bytecode into its ASM representation.
 * @param bytecode - the authentication bytecode to disassemble
 */
export const disassembleBytecodeBTC = (bytecode: Uint8Array) =>
  disassembleParsedAuthenticationInstructions(
    OpcodesBTC,
    parseBytecode(bytecode)
  );

/**
 * Create an object where each key is an opcode identifier and each value is
 * the bytecode value (`Uint8Array`) it represents.
 * @param opcodes - An opcode enum, e.g. `OpcodesBCH`
 */
export const generateBytecodeMap = (opcodes: { [opcode: string]: unknown }) =>
  Object.entries(opcodes)
    .filter<[string, number]>(
      (entry): entry is [string, number] => typeof entry[1] === 'number'
    )
    .reduce<{ [opcode: string]: Uint8Array }>(
      (identifiers, pair) => ({
        ...identifiers,
        [pair[0]]: Uint8Array.of(pair[1]),
      }),
      {}
    );

/**
 * Re-assemble a string of disassembled bytecode (see `disassembleBytecode`).
 *
 * @param opcodes - a mapping of opcodes to their respective Uint8Array
 * representation
 * @param disassembledBytecode - the disassembled bytecode to re-assemble
 */
export const assembleBytecode = (
  opcodes: Readonly<{ [opcode: string]: Uint8Array }>,
  disassembledBytecode: string
) => {
  const configuration = {
    opcodes,
    scripts: { asm: disassembledBytecode },
  };
  return createCompilerCommonSynchronous<
    typeof configuration,
    AuthenticationProgramStateCommon
  >(configuration).generateBytecode('asm', {});
};

/**
 * Re-assemble a string of disassembled BCH bytecode (see
 * `disassembleBytecodeBCH`).
 *
 * Note, this method performs automatic minimization of push instructions.
 *
 * @param disassembledBytecode - the disassembled BCH bytecode to re-assemble
 */
export const assembleBytecodeBCH = (disassembledBytecode: string) =>
  assembleBytecode(generateBytecodeMap(OpcodesBCH2022), disassembledBytecode);

/**
 * Re-assemble a string of disassembled BCH bytecode (see
 * `disassembleBytecodeBTC`).
 *
 * Note, this method performs automatic minimization of push instructions.
 *
 * @param disassembledBytecode - the disassembled BTC bytecode to re-assemble
 */
export const assembleBytecodeBTC = (disassembledBytecode: string) =>
  assembleBytecode(generateBytecodeMap(OpcodesBTC), disassembledBytecode);

const getInstructionLengthBytes = (
  instruction: AuthenticationInstructionPush
) => {
  const { opcode } = instruction;
  const expectedLength = lengthBytesForPushOpcode(opcode);
  return expectedLength === uint8Bytes
    ? Uint8Array.of(instruction.data.length)
    : expectedLength === uint16Bytes
    ? numberToBinUint16LE(instruction.data.length)
    : numberToBinUint32LE(instruction.data.length);
};

/**
 * Re-encode a valid authentication instruction.
 * @param instruction - the instruction to encode
 */
export const encodeAuthenticationInstruction = (
  instruction: AuthenticationInstruction
) =>
  Uint8Array.from([
    instruction.opcode,
    ...('data' in instruction
      ? [
          ...(isPushData(instruction.opcode)
            ? getInstructionLengthBytes(instruction)
            : []),
          ...instruction.data,
        ]
      : []),
  ]);

/**
 * Re-encode a malformed authentication instruction.
 * @param instruction - the malformed instruction to encode
 */
export const encodeParsedAuthenticationInstructionMalformed = (
  instruction: ParsedAuthenticationInstructionMalformed
) => {
  const { opcode } = instruction;

  if (hasMalformedLength(instruction)) {
    return Uint8Array.from([opcode, ...instruction.length]);
  }

  if (isPushData(opcode)) {
    return Uint8Array.from([
      opcode,
      ...(opcode === CommonPushOpcodes.OP_PUSHDATA_1
        ? Uint8Array.of(instruction.expectedDataBytes)
        : opcode === CommonPushOpcodes.OP_PUSHDATA_2
        ? numberToBinUint16LE(instruction.expectedDataBytes)
        : numberToBinUint32LE(instruction.expectedDataBytes)),
      ...instruction.data,
    ]);
  }

  return Uint8Array.from([opcode, ...instruction.data]);
};

/**
 * Re-encode a potentially-malformed authentication instruction.
 * @param instruction - the potentially-malformed instruction to encode
 */
export const encodeParsedAuthenticationInstruction = (
  instruction: ParsedAuthenticationInstruction
): Uint8Array =>
  authenticationInstructionIsMalformed(instruction)
    ? encodeParsedAuthenticationInstructionMalformed(instruction)
    : encodeAuthenticationInstruction(instruction);

/**
 * Re-encode an array of valid authentication instructions.
 * @param instructions - the array of valid instructions to encode
 */
export const encodeAuthenticationInstructions = (
  instructions: readonly AuthenticationInstruction[]
) => flattenBinArray(instructions.map(encodeAuthenticationInstruction));

/**
 * Re-encode an array of potentially-malformed authentication instructions.
 * @param instructions - the array of instructions to encode
 */
export const encodeParsedAuthenticationInstructions = (
  instructions: readonly ParsedAuthenticationInstruction[]
) => flattenBinArray(instructions.map(encodeParsedAuthenticationInstruction));
