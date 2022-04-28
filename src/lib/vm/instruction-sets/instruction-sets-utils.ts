import {
  binToHex,
  createCompilerCommon,
  flattenBinArray,
  numberToBinUint16LE,
  numberToBinUint32LE,
} from '../../lib.js';
import type { AuthenticationProgramStateCommon } from '../vm';

import type {
  AuthenticationInstruction,
  AuthenticationInstructionMalformed,
  AuthenticationInstructionMaybeMalformed,
  AuthenticationInstructionPush,
  AuthenticationInstructionPushMalformedLength,
  AuthenticationInstructions,
  AuthenticationInstructionsMalformed,
  AuthenticationInstructionsMaybeMalformed,
} from './instruction-sets';
import { OpcodesBCH, OpcodesBTC } from './instruction-sets.js';

/**
 * A type-guard that checks if the provided instruction is malformed.
 * @param instruction - the instruction to check
 */
export const authenticationInstructionIsMalformed = (
  instruction: AuthenticationInstructionMaybeMalformed
): instruction is AuthenticationInstructionMalformed =>
  'malformed' in instruction;

/**
 * A type-guard that checks if the final instruction in the provided array of
 * instructions is malformed. (Only the final instruction can be malformed.)
 * @param instructions - the array of instructions to check
 */
export const authenticationInstructionsAreMalformed = (
  instructions: AuthenticationInstructionsMaybeMalformed
): instructions is AuthenticationInstructionsMalformed =>
  instructions.length > 0 &&
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  authenticationInstructionIsMalformed(instructions[instructions.length - 1]!);

export const authenticationInstructionsArePushInstructions = (
  instructions: AuthenticationInstructions
): instructions is AuthenticationInstructionPush[] =>
  instructions.every((instruction) => 'data' in instruction);

const enum CommonPushOpcodes {
  OP_0 = 0x00,
  OP_PUSHDATA_1 = 0x4c,
  OP_PUSHDATA_2 = 0x4d,
  OP_PUSHDATA_4 = 0x4e,
}

const uint8Bytes = 1;
const uint16Bytes = 2;
const uint32Bytes = 4;

/**
 * Decode a little endian number of `length` from virtual machine `bytecode`
 * beginning at `index`.
 */
export const decodeLittleEndianNumber = (
  bytecode: Uint8Array,
  index: number,
  length: typeof uint8Bytes | typeof uint16Bytes | typeof uint32Bytes
) => {
  const view = new DataView(bytecode.buffer, index, length);
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
 * @param opcode - an opcode between 0x00 and 0xff
 */
export const opcodeToPushLength = (
  opcode: number
): typeof uint8Bytes | typeof uint16Bytes | typeof uint32Bytes | 0 =>
  ({
    [CommonPushOpcodes.OP_PUSHDATA_1]: uint8Bytes as typeof uint8Bytes,
    [CommonPushOpcodes.OP_PUSHDATA_2]: uint16Bytes as typeof uint16Bytes,
    [CommonPushOpcodes.OP_PUSHDATA_4]: uint32Bytes as typeof uint32Bytes,
  }[opcode] ?? 0);

/**
 * Decode one instruction from the provided virtual machine bytecode.
 *
 * Returns an object with an `instruction` referencing a
 * {@link AuthenticationInstructionMaybeMalformed}, and a `nextIndex` indicating
 * the next index from which to read. If the next index is greater than or equal
 * to the length of the bytecode, the bytecode has been fully decoded.
 *
 * The final {@link AuthenticationInstructionMaybeMalformed} in the bytecode may
 * be malformed if 1) the final operation is a push and 2) too few bytes remain
 * for the push operation to complete.
 *
 * @param bytecode - the virtual machine bytecode from which to read the next
 * instruction
 * @param index - the index from which to begin reading
 */
// eslint-disable-next-line complexity
export const decodeAuthenticationInstruction = (
  bytecode: Uint8Array,
  index: number
): {
  instruction: AuthenticationInstructionMaybeMalformed;
  nextIndex: number;
} => {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const opcode = bytecode[index]!;
  if (opcode > CommonPushOpcodes.OP_PUSHDATA_4) {
    return {
      instruction: {
        opcode,
      },
      nextIndex: index + 1,
    };
  }
  const lengthBytes = opcodeToPushLength(opcode);

  if (lengthBytes !== 0 && index + lengthBytes >= bytecode.length) {
    const sliceStart = index + 1;
    const sliceEnd = sliceStart + lengthBytes;
    return {
      instruction: {
        expectedLengthBytes: lengthBytes,
        length: bytecode.slice(sliceStart, sliceEnd),
        malformed: true,
        opcode,
      },
      nextIndex: sliceEnd,
    };
  }

  const dataBytes =
    lengthBytes === 0
      ? opcode
      : decodeLittleEndianNumber(bytecode, index + 1, lengthBytes);
  const dataStart = index + 1 + lengthBytes;
  const dataEnd = dataStart + dataBytes;
  return {
    instruction: {
      data: bytecode.slice(dataStart, dataEnd),
      ...(dataEnd > bytecode.length
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
 * @param instruction - the {@link AuthenticationInstruction} to clone.
 * @returns A copy of the provided {@link AuthenticationInstruction}.
 */
export const cloneAuthenticationInstruction = (
  instruction: Readonly<AuthenticationInstruction>
): AuthenticationInstruction => ({
  ...('data' in instruction ? { data: instruction.data } : {}),
  opcode: instruction.opcode,
});

/**
 * Decode authentication virtual machine bytecode (`lockingBytecode` or
 * `unlockingBytecode`) into {@link AuthenticationInstructionsMaybeMalformed}.
 * The method {@link authenticationInstructionsAreMalformed} can be used to
 * check if these instructions include a malformed instruction. If not, they are
 * valid {@link AuthenticationInstructions}.
 *
 * @param bytecode - the authentication virtual machine bytecode to decode
 */
export const decodeAuthenticationInstructions = (bytecode: Uint8Array) => {
  const instructions = [] as AuthenticationInstructionsMaybeMalformed;
  // eslint-disable-next-line functional/no-let
  let i = 0;
  // eslint-disable-next-line functional/no-loop-statement
  while (i < bytecode.length) {
    const { instruction, nextIndex } = decodeAuthenticationInstruction(
      bytecode,
      i
    );
    // eslint-disable-next-line functional/no-expression-statement
    i = nextIndex;
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    (instructions as AuthenticationInstruction[]).push(
      instruction as AuthenticationInstruction
    );
  }
  return instructions;
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
  instruction: AuthenticationInstructionMalformed
): instruction is AuthenticationInstructionPushMalformedLength =>
  'length' in instruction;
const isPushData = (pushOpcode: number) =>
  pushOpcode >= CommonPushOpcodes.OP_PUSHDATA_1;

/**
 * Disassemble a malformed authentication instruction into a string description.
 * @param opcodes - a mapping of possible opcodes to their string representation
 * @param instruction - the {@link AuthenticationInstructionMalformed} to
 * disassemble
 */
export const disassembleAuthenticationInstructionMalformed = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instruction: AuthenticationInstructionMalformed
): string =>
  `${opcodes[instruction.opcode] ?? 'OP_UNKNOWN'} ${
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
  `${opcodes[instruction.opcode] ?? 'OP_UNKNOWN'}${
    'data' in instruction && isMultiWordPush(instruction.opcode)
      ? ` ${
          isPushData(instruction.opcode) ? `${instruction.data.length} ` : ''
        }${formatAsmPushHex(instruction.data)}`
      : ''
  }`;

/**
 * Disassemble a single {@link AuthenticationInstructionMaybeMalformed} into its
 * ASM representation.
 *
 * @param opcodes - a mapping of possible opcodes to their string representation
 * @param instruction - the instruction to disassemble
 */
export const disassembleAuthenticationInstructionMaybeMalformed = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instruction: AuthenticationInstructionMaybeMalformed
): string =>
  authenticationInstructionIsMalformed(instruction)
    ? disassembleAuthenticationInstructionMalformed(opcodes, instruction)
    : disassembleAuthenticationInstruction(opcodes, instruction);

/**
 * Disassemble an array of {@link AuthenticationInstructionMaybeMalformed}
 * (including potentially malformed instructions) into its ASM representation.
 *
 * This method supports disassembling an array including multiple
 * {@link AuthenticationInstructionMaybeMalformed}s, rather than the more
 * constrained {@link AuthenticationInstructionsMaybeMalformed} (may only
 * include one malformed instruction as the last item in the array).
 *
 * @param opcodes - a mapping of possible opcodes to their string representation
 * @param instructions - the array of instructions to disassemble
 */
export const disassembleAuthenticationInstructionsMaybeMalformed = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  instructions: readonly AuthenticationInstructionMaybeMalformed[]
): string =>
  instructions
    .map((instruction) =>
      disassembleAuthenticationInstructionMaybeMalformed(opcodes, instruction)
    )
    .join(' ');

/**
 * Disassemble authentication bytecode into a lossless ASM representation. (All
 * push operations are represented with the same opcodes used in the bytecode,
 * even when non-minimally encoded.)
 *
 * @param opcodes - a mapping of possible opcodes to their string representation
 * @param bytecode - the authentication bytecode to disassemble
 */
export const disassembleBytecode = (
  opcodes: Readonly<{ [opcode: number]: string }>,
  bytecode: Uint8Array
) =>
  disassembleAuthenticationInstructionsMaybeMalformed(
    opcodes,
    decodeAuthenticationInstructions(bytecode)
  );

/**
 * Disassemble BCH authentication bytecode into its ASM representation.
 *
 * Note, this method automatically uses the latest BCH instruction set. To
 * manually select an instruction set, use {@link disassembleBytecode}.
 *
 * @param bytecode - the virtual machine bytecode to disassemble
 */
export const disassembleBytecodeBCH = (bytecode: Uint8Array) =>
  disassembleAuthenticationInstructionsMaybeMalformed(
    OpcodesBCH,
    decodeAuthenticationInstructions(bytecode)
  );

/**
 * Disassemble BTC authentication bytecode into its ASM representation.
 *
 * Note, this method automatically uses the latest BTC instruction set. To
 * manually select an instruction set, use {@link disassembleBytecode}.
 *
 * @param bytecode - the virtual machine bytecode to disassemble
 */
export const disassembleBytecodeBTC = (bytecode: Uint8Array) =>
  disassembleAuthenticationInstructionsMaybeMalformed(
    OpcodesBTC,
    decodeAuthenticationInstructions(bytecode)
  );

/**
 * Create an object where each key is an opcode identifier and each value is
 * the bytecode value (`Uint8Array`) it represents.
 * @param opcodes - An opcode enum, e.g. {@link OpcodesBCH}
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
 * Re-assemble a string of disassembled bytecode
 * (see {@link disassembleBytecode}).
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
  return createCompilerCommon<
    typeof configuration,
    AuthenticationProgramStateCommon
  >(configuration).generateBytecode({ data: {}, scriptId: 'asm' });
};

/**
 * Re-assemble a string of disassembled BCH bytecode; see
 * {@link disassembleBytecodeBCH}.
 *
 * Note, this method performs automatic minimization of push instructions.
 *
 * @param disassembledBytecode - the disassembled BCH bytecode to re-assemble
 */
export const assembleBytecodeBCH = (disassembledBytecode: string) =>
  assembleBytecode(generateBytecodeMap(OpcodesBCH), disassembledBytecode);

/**
 * Re-assemble a string of disassembled BCH bytecode; see
 * {@link disassembleBytecodeBTC}.
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
  const expectedLength = opcodeToPushLength(opcode);
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
 * @param instruction - the {@link AuthenticationInstructionMalformed} to encode
 */
export const encodeAuthenticationInstructionMalformed = (
  instruction: AuthenticationInstructionMalformed
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
 * @param instruction - the {@link AuthenticationInstructionMaybeMalformed}
 * to encode
 */
export const encodeAuthenticationInstructionMaybeMalformed = (
  instruction: AuthenticationInstructionMaybeMalformed
): Uint8Array =>
  authenticationInstructionIsMalformed(instruction)
    ? encodeAuthenticationInstructionMalformed(instruction)
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
 * @param instructions - the array of
 * {@link AuthenticationInstructionMaybeMalformed}s to encode
 */
export const encodeAuthenticationInstructionsMaybeMalformed = (
  instructions: readonly AuthenticationInstructionMaybeMalformed[]
) =>
  flattenBinArray(
    instructions.map(encodeAuthenticationInstructionMaybeMalformed)
  );
