import type {
  AuthenticationProgramCommon,
  AuthenticationProgramStateCommon,
  AuthenticationProgramStateControlStack,
  AuthenticationProgramStateMinimum,
  AuthenticationProgramStateStack,
  CompilationContextBCH,
} from '../lib';
import { generateBytecodeMap, Opcodes } from '../lib.js';

import { compilerOperationsCommon } from './compiler-operations.js';
import type {
  AnyCompilerConfiguration,
  BytecodeGenerationResult,
  CompilationData,
  Compiler,
  CompilerConfiguration,
} from './compiler-types';
import { generateScenarioBCH } from './scenarios.js';
import type { CompilationResult } from './template';
import type { AuthenticationTemplate } from './template-types';
import { compileScript } from './template.js';

/**
 * Create a `Compiler.generateBytecode` method given a compiler configuration.
 */
export const createCompilerGenerateBytecodeFunction =
  <
    CompilationContext extends CompilationContextBCH,
    Configuration extends AnyCompilerConfiguration<CompilationContext>,
    ProgramState extends AuthenticationProgramStateControlStack &
      AuthenticationProgramStateMinimum &
      AuthenticationProgramStateStack
  >(
    compilerConfiguration: Configuration
  ) =>
  <Debug extends boolean>({
    data,
    debug,
    scriptId,
  }: {
    scriptId: string;
    data: CompilationData<CompilationContext>;
    debug?: boolean;
  }) => {
    const result = compileScript<ProgramState, CompilationContext>(
      scriptId,
      data,
      compilerConfiguration
    );
    return (
      debug === true
        ? result
        : result.success
        ? { bytecode: result.bytecode, success: true }
        : {
            errorType: result.errorType,
            errors: result.errors,
            success: false,
          }
    ) as Debug extends true
      ? CompilationResult<ProgramState>
      : BytecodeGenerationResult<ProgramState>;
  };

/**
 * Create a `Compiler` from the provided compiler configuration. This method
 * requires a full `CompilerConfiguration` and does not instantiate any new
 * crypto or VM implementations.
 *
 * @param configuration - the configuration from which to create the
 * compiler
 */
export const compilerConfigurationToCompilerBCH = <
  Configuration extends AnyCompilerConfiguration<CompilationContextBCH>,
  ProgramState extends AuthenticationProgramStateControlStack &
    AuthenticationProgramStateMinimum &
    AuthenticationProgramStateStack
>(
  configuration: Configuration
): Compiler<CompilationContextBCH, Configuration, ProgramState> => {
  const generateBytecode =
    createCompilerGenerateBytecodeFunction(configuration);
  return {
    configuration,
    generateBytecode,
    generateScenario: ({ unlockingScriptId, scenarioId, debug }) =>
      generateScenarioBCH(
        {
          configuration,
          generateBytecode,
          scenarioId,
          unlockingScriptId,
        },
        debug
      ),
  };
};

const nullHashLength = 32;

/**
 * A common `createAuthenticationProgram` implementation for most compilers.
 *
 * Accepts the compiled contents of an evaluation and produces a
 * `AuthenticationProgramCommon` which can be evaluated to produce the resulting
 * program state.
 *
 * The precise shape of the authentication program produced by this method is
 * critical to the determinism of CashAssembly evaluations for the compiler in
 * which it is used, it therefore must be standardized between compiler
 * implementations.
 *
 * @param evaluationBytecode - the compiled bytecode to incorporate in the
 * created authentication program
 */
export const createAuthenticationProgramEvaluationCommon = (
  evaluationBytecode: Uint8Array
): AuthenticationProgramCommon => ({
  inputIndex: 0,
  sourceOutputs: [
    {
      lockingBytecode: evaluationBytecode,
      valueSatoshis: Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0]),
    },
  ],
  transaction: {
    inputs: [
      {
        outpointIndex: 0,
        outpointTransactionHash: new Uint8Array(nullHashLength),
        sequenceNumber: 0,
        unlockingBytecode: Uint8Array.of(),
      },
    ],
    locktime: 0,
    outputs: [
      {
        lockingBytecode: Uint8Array.of(),
        valueSatoshis: Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0]),
      },
    ],
    version: 0,
  },
});

/**
 * Synchronously create a compiler using the default common compiler
 * configuration. Because this compiler has no access to Secp256k1, Sha256, or a
 * VM, it cannot compile evaluations or operations which require key derivation
 * or hashing.
 *
 * @param scriptsAndOverrides - a compiler configuration from which properties
 * will be used to override properties of the default common compiler
 * configuration – must include the `scripts` property
 */
export const createCompilerCommonSynchronous = <
  Configuration extends AnyCompilerConfiguration<CompilationContextBCH>,
  ProgramState extends AuthenticationProgramStateCommon
>(
  scriptsAndOverrides: Configuration
): Compiler<CompilationContextBCH, Configuration, ProgramState> =>
  compilerConfigurationToCompilerBCH<Configuration, ProgramState>({
    ...{
      createAuthenticationProgram: createAuthenticationProgramEvaluationCommon,
      opcodes: generateBytecodeMap(Opcodes),
      operations: compilerOperationsCommon,
    },
    ...scriptsAndOverrides,
  });

/**
 * Create a partial `CompilerConfiguration` from an `AuthenticationTemplate` by
 * extracting and formatting the `scripts` and `variables` properties.
 *
 * Note, if this `AuthenticationTemplate` might be malformed, first validate it
 * with `importAuthenticationTemplate`.
 *
 * @param template - the `AuthenticationTemplate` from which to extract the
 * compiler configuration
 */
export const authenticationTemplateToCompilerConfiguration = (
  template: AuthenticationTemplate
): Pick<
  CompilerConfiguration,
  | 'entityOwnership'
  | 'lockingScriptTypes'
  | 'scenarios'
  | 'scripts'
  | 'unlockingScripts'
  | 'unlockingScriptTimeLockTypes'
  | 'variables'
> => {
  /**
   * Template scripts including virtualized test scripts.
   */
  const virtualizedScripts: AuthenticationTemplate['scripts'] = Object.entries(
    template.scripts
  ).reduce<AuthenticationTemplate['scripts']>((all, [scriptId, script]) => {
    if ('tests' in script) {
      return {
        ...all,
        ...Object.entries(script.tests).reduce<
          AuthenticationTemplate['scripts']
        >((tests, [testId, test]) => {
          const pushTestedScript = script.pushed === true;
          const checkScriptId = `${scriptId}.${testId}.check`;
          const virtualizedLockingScriptId = `${scriptId}.${testId}.lock`;
          const virtualizedUnlockingScriptId = `${scriptId}.${testId}.unlock`;
          return {
            ...tests,
            [checkScriptId]: { script: test.check },
            [virtualizedLockingScriptId]: {
              script: pushTestedScript
                ? `<${scriptId}> ${checkScriptId}`
                : `${scriptId} ${checkScriptId}`,
            },
            [virtualizedUnlockingScriptId]: {
              script: test.setup ?? '',
              unlocks: virtualizedLockingScriptId,
            },
          };
        }, {}),
      };
    }
    return all;
  }, {});
  const allScripts = {
    ...template.scripts,
    ...virtualizedScripts,
  };
  const scripts = Object.entries(allScripts).reduce<
    CompilerConfiguration['scripts']
  >((all, [id, def]) => ({ ...all, [id]: def.script }), {});
  const variables = Object.values(template.entities).reduce<
    CompilerConfiguration['variables']
  >((all, entity) => ({ ...all, ...entity.variables }), {});
  const entityOwnership = Object.entries(template.entities).reduce<
    CompilerConfiguration['entityOwnership']
  >(
    (all, [entityId, entity]) => ({
      ...all,
      ...Object.keys(entity.variables ?? {}).reduce(
        (entityVariables, variableId) => ({
          ...entityVariables,
          [variableId]: entityId,
        }),
        {}
      ),
    }),
    {}
  );
  const unlockingScripts = Object.entries(allScripts).reduce<
    CompilerConfiguration['unlockingScripts']
  >(
    (all, [id, def]) =>
      'unlocks' in def && (def.unlocks as string | undefined) !== undefined
        ? { ...all, [id]: def.unlocks }
        : all,
    {}
  );
  const unlockingScriptTimeLockTypes = Object.entries(allScripts).reduce<
    CompilerConfiguration['unlockingScriptTimeLockTypes']
  >(
    (all, [id, def]) =>
      'timeLockType' in def && def.timeLockType !== undefined
        ? { ...all, [id]: def.timeLockType }
        : all,
    {}
  );
  const lockingScriptTypes = Object.entries(allScripts).reduce<
    CompilerConfiguration['lockingScriptTypes']
  >(
    (all, [id, def]) =>
      'lockingType' in def &&
      (def.lockingType as string | undefined) !== undefined
        ? { ...all, [id]: def.lockingType }
        : all,
    {}
  );
  const scenarios =
    template.scenarios === undefined
      ? undefined
      : Object.entries(template.scenarios).reduce<
          CompilerConfiguration['scenarios']
        >((all, [id, def]) => ({ ...all, [id]: def }), {});
  return {
    entityOwnership,
    lockingScriptTypes,
    ...(scenarios === undefined ? {} : { scenarios }),
    scripts,
    unlockingScriptTimeLockTypes,
    unlockingScripts,
    variables,
  };
};
