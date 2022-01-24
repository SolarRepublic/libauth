export interface AuthenticationInstructionPush {
  /**
   * The data to be pushed to the stack.
   */
  readonly data: Uint8Array;
  /**
   * The opcode used to push this data.
   */
  readonly opcode: number;
}

export interface AuthenticationInstructionOperation {
  /**
   * The opcode of this instruction's operation.
   */
  readonly opcode: number;
}

/**
 * A properly-formed instruction used by an `AuthenticationVirtualMachine`.
 */
export type AuthenticationInstruction =
  | AuthenticationInstructionOperation
  | AuthenticationInstructionPush;

export type AuthenticationInstructions = AuthenticationInstruction[];

type Uint8Bytes = 1;
type Uint16Bytes = 2;
type Uint32Bytes = 4;
export interface ParsedAuthenticationInstructionPushMalformedLength {
  /**
   * The expected number of length bytes (`length.length`) for this `PUSHDATA` operation.
   */
  readonly expectedLengthBytes: Uint8Bytes | Uint16Bytes | Uint32Bytes;
  /**
   * The length `Uint8Array` provided. This instruction is malformed because the length of this `Uint8Array` is shorter than the `expectedLengthBytes`.
   */
  readonly length: Uint8Array;
  readonly malformed: true;
  readonly opcode: number;
}

export interface ParsedAuthenticationInstructionPushMalformedData {
  /**
   * The data `Uint8Array` provided. This instruction is malformed because the length of this `Uint8Array` is shorter than the `expectedDataBytes`.
   */
  readonly data: Uint8Array;
  /**
   * The expected number of data bytes (`data.length`) for this push operation.
   */
  readonly expectedDataBytes: number;
  readonly malformed: true;
  readonly opcode: number;
}

export type ParsedAuthenticationInstructionMalformed =
  | ParsedAuthenticationInstructionPushMalformedData
  | ParsedAuthenticationInstructionPushMalformedLength;

/**
 * A potentially-malformed `AuthenticationInstruction`. If `malformed` is
 * `true`, this could be either
 * `ParsedAuthenticationInstructionPushMalformedLength` or
 * `ParsedAuthenticationInstructionPushMalformedData`
 *
 * If the final instruction is a push operation which requires more bytes than
 * are available in the remaining portion of an encoded script, that
 * instruction will have a `malformed` property with a value of `true`.
 */
export type ParsedAuthenticationInstruction =
  | AuthenticationInstruction
  | ParsedAuthenticationInstructionMalformed;

/**
 * An array of authentication instructions which may end with a malformed
 * instruction.
 */
export type ParsedAuthenticationInstructions =
  | [...AuthenticationInstruction[], ParsedAuthenticationInstruction]
  | [];
