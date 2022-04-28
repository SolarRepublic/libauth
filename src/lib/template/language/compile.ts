import type {
  AuthenticationProgramStateControlStack,
  AuthenticationProgramStateMinimum,
  AuthenticationProgramStateStack,
  AuthenticationVirtualMachine,
  CompilationContextBCH,
  CompilationContextCommon,
} from '../../lib';
import type { CompilationData, CompilerConfiguration } from '../template';
import { createCompilerCommon } from '../template.js';

import type {
  CompilationResult,
  CompilationResultSuccess,
} from './language-types';
import { getResolutionErrors } from './language-utils.js';
import { parseScript } from './parse.js';
import { reduceScript } from './reduce.js';
import { createIdentifierResolver, resolveScriptSegment } from './resolve.js';

/**
 * A text-formatting method to pretty-print the list of expected inputs
 * (`Encountered unexpected input while parsing script. Expected ...`). If
 * present, the `EOF` expectation is always moved to the end of the list.
 * @param expectedArray - the alphabetized list of expected inputs produced by
 * `parseScript`
 */
export const describeExpectedInput = (expectedArray: string[]) => {
  /**
   * The constant used by the parser to denote the end of the input
   */
  const EOF = 'EOF';
  const newArray = expectedArray.filter((value) => value !== EOF);
  // eslint-disable-next-line functional/no-conditional-statement
  if (newArray.length !== expectedArray.length) {
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    newArray.push('the end of the script');
  }
  const withoutLastElement = newArray.slice(0, newArray.length - 1);
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const lastElement = newArray[newArray.length - 1]!;
  const arrayRequiresCommas = 3;
  const arrayRequiresOr = 2;
  return `Encountered unexpected input while parsing script. Expected ${
    newArray.length >= arrayRequiresCommas
      ? withoutLastElement.join(', ').concat(`, or ${lastElement}`)
      : newArray.length === arrayRequiresOr
      ? newArray.join(' or ')
      : lastElement
  }.`;
};

/**
 * This method is generally for internal use. The {@link compileScript} method
 * is the recommended API for direct compilation.
 */
export const compileScriptContents = <
  ProgramState extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateStack = AuthenticationProgramStateControlStack &
    AuthenticationProgramStateStack,
  CompilationContext = unknown
>({
  data,
  configuration,
  script,
}: {
  script: string;
  data: CompilationData<CompilationContext>;
  configuration: CompilerConfiguration<CompilationContext>;
}): CompilationResult<ProgramState> => {
  const parseResult = parseScript(script);
  if (!parseResult.status) {
    return {
      errorType: 'parse',
      errors: [
        {
          error: describeExpectedInput(parseResult.expected),
          range: {
            endColumn: parseResult.index.column,
            endLineNumber: parseResult.index.line,
            startColumn: parseResult.index.column,
            startLineNumber: parseResult.index.line,
          },
        },
      ],
      success: false,
    };
  }
  const resolver = createIdentifierResolver({ configuration, data });
  const resolvedScript = resolveScriptSegment(parseResult.value, resolver);
  const resolutionErrors = getResolutionErrors(resolvedScript);
  if (resolutionErrors.length !== 0) {
    return {
      errorType: 'resolve',
      errors: resolutionErrors,
      parse: parseResult.value,
      resolve: resolvedScript,
      success: false,
    };
  }
  const reduction = reduceScript<ProgramState, unknown, unknown>(
    resolvedScript,
    configuration.vm,
    configuration.createAuthenticationProgram
  );
  return {
    ...(reduction.errors === undefined
      ? { bytecode: reduction.bytecode, success: true }
      : { errorType: 'reduce', errors: reduction.errors, success: false }),
    parse: parseResult.value,
    reduce: reduction,
    resolve: resolvedScript,
  };
};

const emptyRange = () => ({
  endColumn: 0,
  endLineNumber: 0,
  startColumn: 0,
  startLineNumber: 0,
});

/**
 * This method is generally for internal use. The {@link compileScript} method
 * is the recommended API for direct compilation.
 */
export const compileScriptRaw = <
  ProgramState extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateMinimum &
    AuthenticationProgramStateStack = AuthenticationProgramStateControlStack &
    AuthenticationProgramStateMinimum &
    AuthenticationProgramStateStack,
  CompilationContext = unknown
>({
  data,
  configuration,
  scriptId,
}: {
  data: CompilationData<CompilationContext>;
  configuration: CompilerConfiguration<CompilationContext>;
  scriptId: string;
}): CompilationResult<ProgramState> => {
  const script = configuration.scripts[scriptId];
  if (script === undefined) {
    return {
      errorType: 'parse',
      errors: [
        {
          error: `No script with an ID of "${scriptId}" was provided in the compiler configuration.`,
          range: emptyRange(),
        },
      ],
      success: false,
    };
  }

  if (configuration.sourceScriptIds?.includes(scriptId) === true) {
    return {
      errorType: 'parse',
      errors: [
        {
          error: `A circular dependency was encountered: script "${scriptId}" relies on itself to be generated. (Source scripts: ${configuration.sourceScriptIds.join(
            ' → '
          )})`,
          range: emptyRange(),
        },
      ],
      success: false,
    };
  }
  const sourceScriptIds =
    configuration.sourceScriptIds === undefined
      ? [scriptId]
      : [...configuration.sourceScriptIds, scriptId];

  return compileScriptContents<ProgramState, CompilationContext>({
    configuration: { ...configuration, sourceScriptIds },
    data,
    script,
  });
};

export const compileScriptP2sh20Locking = <
  ResolvedTransaction,
  AuthenticationProgram,
  ProgramState
>({
  lockingBytecode,
  vm,
}: {
  lockingBytecode: Uint8Array;
  vm:
    | AuthenticationVirtualMachine<
        ResolvedTransaction,
        AuthenticationProgram,
        ProgramState
      >
    | undefined;
}) => {
  const compiler = createCompilerCommon({
    scripts: {
      p2sh20Locking: 'OP_HASH160 <$(<lockingBytecode> OP_HASH160)> OP_EQUAL',
    },
    variables: { lockingBytecode: { type: 'AddressData' } },
    vm,
  });
  return compiler.generateBytecode({
    data: {
      bytecode: { lockingBytecode },
    },
    scriptId: 'p2sh20Locking',
  });
};

export const compileScriptP2sh20Unlocking = <ProgramState>({
  lockingBytecode,
  unlockingBytecode,
}: {
  lockingBytecode: Uint8Array;
  unlockingBytecode: Uint8Array;
}) => {
  const compiler = createCompilerCommon({
    scripts: {
      p2sh20Unlocking: 'unlockingBytecode <lockingBytecode>',
    },
    variables: {
      lockingBytecode: { type: 'AddressData' },
      unlockingBytecode: { type: 'AddressData' },
    },
  });
  return compiler.generateBytecode({
    data: { bytecode: { lockingBytecode, unlockingBytecode } },
    scriptId: 'p2sh20Unlocking',
  }) as CompilationResultSuccess<ProgramState>;
};

/**
 * Parse, resolve, and reduce the selected script using the provided `data` and
 * `configuration`.
 *
 * Note, locktime validation only occurs if `compilationContext` is provided in
 * the configuration.
 */
// eslint-disable-next-line complexity
export const compileScript = <
  ProgramState extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateMinimum &
    AuthenticationProgramStateStack = AuthenticationProgramStateControlStack &
    AuthenticationProgramStateMinimum &
    AuthenticationProgramStateStack,
  CompilationContext extends CompilationContextCommon = CompilationContextBCH
>(
  scriptId: string,
  data: CompilationData<CompilationContext>,
  configuration: CompilerConfiguration<CompilationContext>
): CompilationResult<ProgramState> => {
  const locktimeDisablingSequenceNumber = 0xffffffff;
  const lockTimeTypeBecomesTimestamp = 500000000;
  if (data.compilationContext?.transaction.locktime !== undefined) {
    if (
      configuration.unlockingScriptTimeLockTypes?.[scriptId] === 'height' &&
      data.compilationContext.transaction.locktime >=
        lockTimeTypeBecomesTimestamp
    ) {
      return {
        errorType: 'parse',
        errors: [
          {
            error: `The script "${scriptId}" requires a height-based locktime (less than 500,000,000), but this transaction uses a timestamp-based locktime ("${data.compilationContext.transaction.locktime}").`,
            range: emptyRange(),
          },
        ],
        success: false,
      };
    }
    if (
      configuration.unlockingScriptTimeLockTypes?.[scriptId] === 'timestamp' &&
      data.compilationContext.transaction.locktime <
        lockTimeTypeBecomesTimestamp
    ) {
      return {
        errorType: 'parse',
        errors: [
          {
            error: `The script "${scriptId}" requires a timestamp-based locktime (greater than or equal to 500,000,000), but this transaction uses a height-based locktime ("${data.compilationContext.transaction.locktime}").`,
            range: emptyRange(),
          },
        ],
        success: false,
      };
    }
  }

  if (
    data.compilationContext?.transaction.inputs[
      data.compilationContext.inputIndex
    ]?.sequenceNumber !== undefined &&
    configuration.unlockingScriptTimeLockTypes?.[scriptId] !== undefined &&
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    data.compilationContext.transaction.inputs[
      data.compilationContext.inputIndex
    ]!.sequenceNumber === locktimeDisablingSequenceNumber
  ) {
    return {
      errorType: 'parse',
      errors: [
        {
          error: `The script "${scriptId}" requires a locktime, but this input's sequence number is set to disable transaction locktime (0xffffffff). This will cause the OP_CHECKLOCKTIMEVERIFY operation to error when the transaction is verified. To be valid, this input must use a sequence number that does not disable locktime.`,
          range: emptyRange(),
        },
      ],
      success: false,
    };
  }

  const rawResult = compileScriptRaw<ProgramState, CompilationContext>({
    configuration,
    data,
    scriptId,
  });

  if (!rawResult.success) {
    return rawResult;
  }

  const unlocks = configuration.unlockingScripts?.[scriptId];
  const unlockingScriptType =
    unlocks === undefined
      ? undefined
      : configuration.lockingScriptTypes?.[unlocks];
  const isP2sh20UnlockingScript = unlockingScriptType === 'p2sh20';

  const lockingScriptType = configuration.lockingScriptTypes?.[scriptId];
  const isP2sh20LockingScript = lockingScriptType === 'p2sh20';

  if (isP2sh20LockingScript) {
    const transformedResult = compileScriptP2sh20Locking<
      unknown,
      unknown,
      ProgramState
    >({
      lockingBytecode: rawResult.bytecode,
      vm: configuration.vm,
    });
    if (!transformedResult.success) {
      return transformedResult;
    }
    return {
      ...rawResult,
      bytecode: transformedResult.bytecode,
      transformed: 'p2sh20-locking',
    };
  }

  if (isP2sh20UnlockingScript) {
    const lockingBytecodeResult = compileScriptRaw<
      ProgramState,
      CompilationContext
    >({
      configuration,
      data,
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      scriptId: unlocks!,
    });
    if (!lockingBytecodeResult.success) {
      return lockingBytecodeResult;
    }
    const transformedResult = compileScriptP2sh20Unlocking<ProgramState>({
      lockingBytecode: lockingBytecodeResult.bytecode,
      unlockingBytecode: rawResult.bytecode,
    });
    return {
      ...rawResult,
      bytecode: transformedResult.bytecode,
      transformed: 'p2sh20-unlocking',
    };
  }

  return rawResult;
};
