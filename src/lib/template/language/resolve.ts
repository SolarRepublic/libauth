import { bigIntToScriptNumber, hexToBin, utf8ToBin } from '../../lib.js';
import type {
  AnyCompilerConfiguration,
  AuthenticationTemplateVariable,
  CompilationData,
  CompilerConfiguration,
  CompilerOperation,
  CompilerOperationResult,
} from '../template';

import { compileScriptRaw } from './compile.js';
import type {
  CashAssemblyScriptSegment,
  CompilationResultSuccess,
  IdentifierResolutionFunction,
  MarkedNode,
  Range,
  ResolvedScript,
  ResolvedSegment,
} from './language';
import {
  IdentifierResolutionErrorType,
  IdentifierResolutionType,
  stringifyErrors,
} from './language.js';

const pluckRange = (node: MarkedNode): Range => ({
  endColumn: node.end.column,
  endLineNumber: node.end.line,
  startColumn: node.start.column,
  startLineNumber: node.start.line,
});

const removeNumericSeparators = (numericLiteral: string) =>
  numericLiteral.replace(/_/gu, '');

export const resolveScriptSegment = (
  segment: CashAssemblyScriptSegment,
  resolveIdentifiers: IdentifierResolutionFunction
): ResolvedScript => {
  // eslint-disable-next-line complexity
  const resolved = segment.value.map<ResolvedSegment>((child) => {
    const range = pluckRange(child);
    switch (child.name) {
      case 'Identifier': {
        const identifier = child.value;
        const result = resolveIdentifiers(identifier);
        const ret = result.status
          ? {
              range,
              type: 'bytecode' as const,
              value: result.bytecode,
              ...(result.type === IdentifierResolutionType.opcode
                ? {
                    opcode: identifier,
                  }
                : result.type === IdentifierResolutionType.variable
                ? {
                    ...('debug' in result ? { debug: result.debug } : {}),
                    ...('signature' in result
                      ? { signature: result.signature }
                      : {}),
                    variable: identifier,
                  }
                : // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
                result.type === IdentifierResolutionType.script
                ? { script: identifier, source: result.source }
                : ({ unknown: identifier } as never)),
            }
          : {
              ...('debug' in result ? { debug: result.debug } : {}),
              ...('recoverable' in result && result.recoverable
                ? {
                    missingIdentifier: identifier,
                    owningEntity: result.entityOwnership,
                  }
                : {}),
              range,
              type: 'error' as const,
              value: result.error,
            };
        return ret;
      }
      case 'Push':
        return {
          range,
          type: 'push' as const,
          value: resolveScriptSegment(child.value, resolveIdentifiers),
        };
      case 'Evaluation':
        return {
          range,
          type: 'evaluation' as const,
          value: resolveScriptSegment(child.value, resolveIdentifiers),
        };
      case 'BigIntLiteral':
        return {
          literal: child.value,
          literalType: 'BigIntLiteral' as const,
          range,
          type: 'bytecode' as const,
          value: bigIntToScriptNumber(
            BigInt(removeNumericSeparators(child.value))
          ),
        };
      case 'BinaryLiteral':
        return {
          literal: child.value,
          literalType: 'BinaryLiteral' as const,
          range,
          type: 'bytecode' as const,
          value: bigIntToScriptNumber(
            BigInt(`0b${removeNumericSeparators(child.value)}`)
          ),
        };
      case 'HexLiteral':
        return {
          literal: child.value,
          literalType: 'HexLiteral' as const,
          range,
          type: 'bytecode' as const,
          value: hexToBin(removeNumericSeparators(child.value)),
        };
      case 'UTF8Literal':
        return {
          literal: child.value,
          literalType: 'UTF8Literal' as const,
          range,
          type: 'bytecode' as const,
          value: utf8ToBin(child.value),
        };
      case 'Comment':
        return {
          range,
          type: 'comment' as const,
          value: child.value,
        };
      default:
        return {
          range,
          type: 'error' as const,
          value: `Unrecognized segment: ${(child as { name: string }).name}`,
        };
    }
  });

  return resolved.length === 0
    ? [{ range: pluckRange(segment), type: 'comment' as const, value: '' }]
    : resolved;
};

export enum BuiltInVariables {
  currentBlockTime = 'current_block_time',
  currentBlockHeight = 'current_block_height',
  signingSerialization = 'signing_serialization',
}

const attemptCompilerOperation = <
  CompilationContext,
  Configuration extends AnyCompilerConfiguration<CompilationContext>
>({
  data,
  configuration,
  identifier,
  matchingOperations,
  operationExample = 'operation_identifier',
  operationId,
  variableId,
  variableType,
}: {
  data: CompilationData<CompilationContext>;
  configuration: Configuration;
  identifier: string;
  matchingOperations:
    | CompilerOperation<CompilationContext>
    | { [x: string]: CompilerOperation<CompilationContext> | undefined }
    | undefined;
  operationId: string | undefined;
  variableId: string;
  variableType: string;
  operationExample?: string;
}): CompilerOperationResult<true> => {
  if (matchingOperations === undefined) {
    return {
      error: `The "${variableId}" variable type can not be resolved because the "${variableType}" operation has not been included in this compiler's CompilationEnvironment.`,
      status: 'error',
    };
  }
  if (typeof matchingOperations === 'function') {
    const operation = matchingOperations;
    return operation(identifier, data, configuration);
  }
  if (operationId === undefined) {
    return {
      error: `This "${variableId}" variable could not be resolved because this compiler's "${variableType}" operations require an operation identifier, e.g. '${variableId}.${operationExample}'.`,
      status: 'error',
    };
  }
  const operation = matchingOperations[operationId];
  if (operation === undefined) {
    return {
      error: `The identifier "${identifier}" could not be resolved because the "${variableId}.${operationId}" operation is not available to this compiler.`,
      status: 'error',
    };
  }
  return operation(identifier, data, configuration);
};

/**
 * If the identifier can be successfully resolved as a variable, the result is
 * returned as a Uint8Array. If the identifier references a known variable, but
 * an error occurs in resolving it, the error is returned as a string.
 * Otherwise, the identifier is not recognized as a variable, and this method
 * simply returns `false`.
 *
 * @param identifier - The full identifier used to describe this operation, e.g.
 * `owner.signature.all_outputs`.
 * @param data - The `CompilationData` provided to the compiler
 * @param configuration - The `CompilerConfiguration` provided to the compiler
 */
export const resolveVariableIdentifier = <
  CompilationContext,
  Environment extends AnyCompilerConfiguration<CompilationContext>
>({
  data,
  configuration,
  identifier,
}: {
  data: CompilationData<CompilationContext>;
  configuration: Environment;
  identifier: string;
}): CompilerOperationResult<true> => {
  const [variableId, operationId] = identifier.split('.') as [
    string,
    string | undefined
  ];

  switch (variableId) {
    case BuiltInVariables.currentBlockHeight:
      return attemptCompilerOperation({
        configuration,
        data,
        identifier,
        matchingOperations: configuration.operations?.currentBlockHeight,
        operationId,
        variableId,
        variableType: 'currentBlockHeight',
      });
    case BuiltInVariables.currentBlockTime:
      return attemptCompilerOperation({
        configuration,
        data,
        identifier,
        matchingOperations: configuration.operations?.currentBlockTime,
        operationId,
        variableId,
        variableType: 'currentBlockTime',
      });
    case BuiltInVariables.signingSerialization:
      return attemptCompilerOperation({
        configuration,
        data,
        identifier,
        matchingOperations: configuration.operations?.signingSerialization,
        operationExample: 'version',
        operationId,
        variableId,
        variableType: 'signingSerialization',
      });
    default: {
      const expectedVariable: AuthenticationTemplateVariable | undefined =
        configuration.variables?.[variableId];

      if (expectedVariable === undefined) {
        return { status: 'skip' };
      }
      return attemptCompilerOperation({
        configuration,
        data,
        identifier,
        operationId,
        variableId,
        ...{
          // eslint-disable-next-line @typescript-eslint/naming-convention
          AddressData: {
            matchingOperations: configuration.operations?.addressData,
            variableType: 'addressData',
          },
          // eslint-disable-next-line @typescript-eslint/naming-convention
          HdKey: {
            matchingOperations: configuration.operations?.hdKey,
            operationExample: 'public_key',
            variableType: 'hdKey',
          },
          // eslint-disable-next-line @typescript-eslint/naming-convention
          Key: {
            matchingOperations: configuration.operations?.key,
            operationExample: 'public_key',
            variableType: 'key',
          },
          // eslint-disable-next-line @typescript-eslint/naming-convention
          WalletData: {
            matchingOperations: configuration.operations?.walletData,
            variableType: 'walletData',
          },
        }[expectedVariable.type],
      });
    }
  }
};

/**
 * Compile an internal script identifier.
 *
 * @remarks
 * If the identifier can be successfully resolved as a script, the script is
 * compiled and returned as a CompilationResultSuccess. If an error occurs in
 * compiling it, the error is returned as a string.
 *
 * Otherwise, the identifier is not recognized as a script, and this method
 * simply returns `false`.
 *
 * @param identifier - the identifier of the script to be resolved
 * @param data - the provided CompilationData
 * @param configuration - the provided CompilationEnvironment
 * @param parentIdentifier - the identifier of the script which references the
 * script being resolved (for detecting circular dependencies)
 */
export const resolveScriptIdentifier = <CompilationContext, ProgramState>({
  data,
  configuration,
  identifier,
}: {
  identifier: string;
  data: CompilationData<CompilationContext>;
  configuration: CompilerConfiguration<CompilationContext>;
}): CompilationResultSuccess<ProgramState> | string | false => {
  if ((configuration.scripts[identifier] as string | undefined) === undefined) {
    return false;
  }

  const result = compileScriptRaw({
    configuration,
    data,
    scriptId: identifier,
  });
  if (result.success) {
    return result;
  }

  return `Compilation error in resolved script "${identifier}": ${stringifyErrors(
    result.errors
  )}`;

  /*
   * result.errors.reduce(
   *   (all, { error, range }) =>
   *     `${
   *       all === '' ? '' : `${all}; `
   *     } [${
   *       range.startLineNumber
   *     }, ${range.startColumn}]: ${error}`,
   *   ''
   * );
   */
};

/**
 * Return an `IdentifierResolutionFunction` for use in `resolveScriptSegment`.
 *
 * @param scriptId - the `id` of the script for which the resulting
 * `IdentifierResolutionFunction` will be used.
 * @param configuration - a snapshot of the configuration around `scriptId`. See
 * `CompilationEnvironment` for details.
 * @param data - the actual variable values (private keys, shared wallet data,
 * shared address data, etc.) to use in resolving variables.
 */
export const createIdentifierResolver =
  <CompilationContext>({
    data,
    configuration,
  }: {
    data: CompilationData<CompilationContext>;
    configuration: CompilerConfiguration<CompilationContext>;
  }): IdentifierResolutionFunction =>
  // eslint-disable-next-line complexity
  (identifier: string): ReturnType<IdentifierResolutionFunction> => {
    const opcodeResult: Uint8Array | undefined =
      configuration.opcodes?.[identifier];
    if (opcodeResult !== undefined) {
      return {
        bytecode: opcodeResult,
        status: true,
        type: IdentifierResolutionType.opcode,
      };
    }
    const variableResult = resolveVariableIdentifier({
      configuration,
      data,
      identifier,
    });
    if (variableResult.status !== 'skip') {
      return variableResult.status === 'error'
        ? {
            ...('debug' in variableResult
              ? { debug: variableResult.debug }
              : {}),
            error: variableResult.error,
            ...(configuration.entityOwnership === undefined
              ? {}
              : {
                  entityOwnership:
                    configuration.entityOwnership[identifier.split('.')[0]],
                }),
            recoverable: 'recoverable' in variableResult,
            status: false,
            type: IdentifierResolutionErrorType.variable,
          }
        : {
            ...('debug' in variableResult
              ? { debug: variableResult.debug }
              : {}),
            bytecode: variableResult.bytecode,
            ...('signature' in variableResult
              ? {
                  signature: variableResult.signature,
                }
              : {}),
            status: true,
            type: IdentifierResolutionType.variable,
          };
    }
    const scriptResult = resolveScriptIdentifier({
      configuration,
      data,
      identifier,
    });
    if (scriptResult !== false) {
      return typeof scriptResult === 'string'
        ? {
            error: scriptResult,
            scriptId: identifier,
            status: false,
            type: IdentifierResolutionErrorType.script,
          }
        : {
            bytecode: scriptResult.bytecode,
            source: scriptResult.resolve,
            status: true,
            type: IdentifierResolutionType.script,
          };
    }
    return {
      error: `Unknown identifier "${identifier}".`,
      status: false,
      type: IdentifierResolutionErrorType.unknown,
    };
  };
