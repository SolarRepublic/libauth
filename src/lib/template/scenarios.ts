import type { CompilationContextBCH } from '../lib';
import {
  bigIntToBinUint256BEClamped,
  bigIntToBinUint64LE,
  binToHex,
  deriveHdPrivateNodeFromSeed,
  encodeHdPrivateKey,
  hexToBin,
} from '../lib.js';

import type {
  AnyCompilerConfigurationIgnoreOperations,
  AuthenticationTemplateKey,
  AuthenticationTemplateScenario,
  AuthenticationTemplateScenarioBytecode,
  AuthenticationTemplateScenarioData,
  AuthenticationTemplateScenarioOutput,
  CompilationData,
  CompilationError,
  CompilationResult,
  CompilationResultSuccess,
  Compiler,
  Scenario,
  ScenarioGenerationDebuggingResult,
} from './template';
import {
  CompilerDefaults,
  compileScriptRaw,
  stringifyErrors,
} from './template.js';

/**
 * The default `lockingBytecode` value for scenario outputs is a new empty
 * object (`{}`).
 */
const defaultScenarioOutputLockingBytecode = () => ({});

/**
 * The contents of an `AuthenticationTemplateScenario` without the `name` and
 * `description`.
 */
export type ScenarioDefinition = Pick<
  AuthenticationTemplateScenario,
  'data' | 'sourceOutputs' | 'transaction'
>;

type RequiredTwoLevels<T> = {
  [P in keyof T]-?: Required<T[P]>;
};

/**
 * A scenario definition produced when a child scenario `extends` a parent
 * scenario; this "extended" scenario definition is the same as the parent
 * scenario definition, but any properties defined in the child scenario
 * definition replace those found in the parent scenario definition.
 *
 * All scenarios extend the default scenario, so the `data`, `transaction` (and
 * all `transaction` properties), and `sourceOutputs` properties are guaranteed
 * to be defined in any extended scenario definition.
 */
export type ExtendedScenarioDefinition = Required<
  Pick<ScenarioDefinition, 'data'>
> &
  Required<Pick<ScenarioDefinition, 'sourceOutputs'>> &
  RequiredTwoLevels<Pick<ScenarioDefinition, 'transaction'>>;

/**
 * Given a compiler configuration, generate the default scenario which is
 * extended by all the configuration's scenarios.
 *
 * For details on default scenario generation, see
 * `AuthenticationTemplateScenario.extends`.
 *
 * @param configuration - the compiler configuration from which to generate the
 * default scenario
 */
// eslint-disable-next-line complexity
export const generateDefaultScenarioDefinition = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations<CompilationContext>,
  CompilationContext
>(
  configuration: Configuration
): ExtendedScenarioDefinition | string => {
  const { variables, entityOwnership } = configuration;

  const keyVariableIds =
    variables === undefined
      ? []
      : Object.entries(variables)
          .filter(
            (entry): entry is [string, AuthenticationTemplateKey] =>
              entry[1].type === 'Key'
          )
          .map(([id]) => id);

  const entityIds =
    entityOwnership === undefined
      ? []
      : Object.keys(
          Object.values(entityOwnership).reduce(
            (all, entityId) => ({ ...all, [entityId]: true }),
            {}
          )
        );

  const valueMap = [...keyVariableIds, ...entityIds]
    .sort(([idA], [idB]) => idA.localeCompare(idB))
    .reduce<{ [variableOrEntityId: string]: Uint8Array }>(
      (all, id, index) => ({
        ...all,
        [id]: bigIntToBinUint256BEClamped(BigInt(index + 1)),
      }),
      {}
    );

  const privateKeys =
    variables === undefined
      ? undefined
      : Object.entries(variables).reduce<{ [id: string]: string }>(
          (all, [variableId, variable]) =>
            variable.type === 'Key'
              ? {
                  ...all,
                  [variableId]: binToHex(valueMap[variableId]),
                }
              : all,
          {}
        );

  const defaultScenario: ExtendedScenarioDefinition = {
    data: {
      currentBlockHeight:
        CompilerDefaults.defaultScenarioCurrentBlockHeight as const,
      currentBlockTime:
        CompilerDefaults.defaultScenarioCurrentBlockTime as const,
      ...(privateKeys === undefined || Object.keys(privateKeys).length === 0
        ? {}
        : { keys: { privateKeys } }),
    },
    sourceOutputs: [{ lockingBytecode: ['slot'] }],
    transaction: {
      inputs: [{ unlockingBytecode: ['slot'] }],
      locktime: CompilerDefaults.defaultScenarioTransactionLocktime as const,
      outputs: [{ lockingBytecode: defaultScenarioOutputLockingBytecode() }],
      version: CompilerDefaults.defaultScenarioTransactionVersion as const,
    },
  };

  const hasHdKeys =
    variables === undefined
      ? false
      : Object.values(variables).findIndex(
          (variable) => variable.type === 'HdKey'
        ) !== -1;

  if (!hasHdKeys) {
    return defaultScenario;
  }

  const { sha256, sha512 } = configuration;
  if (sha256 === undefined) {
    return 'An implementations of "sha256" is required to generate defaults for HD keys, but the "sha256" property is not included in this compiler configuration.';
  }
  if (sha512 === undefined) {
    return 'An implementations of "sha512" is required to generate defaults for HD keys, but the "sha512" property is not included in this compiler configuration.';
  }
  const crypto = { sha256, sha512 };

  const hdPrivateKeys = entityIds.reduce((all, entityId) => {
    /**
     * The first 5,000,000,000 seeds have been tested, scenarios are
     * unlikely to exceed this number of entities.
     */
    const assumeValid = true;
    const masterNode = deriveHdPrivateNodeFromSeed(
      valueMap[entityId],
      assumeValid,
      crypto
    );
    const hdPrivateKey = encodeHdPrivateKey(
      {
        network: 'mainnet',
        node: masterNode,
      },
      crypto
    );

    return { ...all, [entityId]: hdPrivateKey };
  }, {});

  return {
    ...defaultScenario,
    data: {
      ...defaultScenario.data,
      hdKeys: {
        addressIndex: CompilerDefaults.defaultScenarioAddressIndex as const,
        hdPrivateKeys,
      },
    },
  };
};

/**
 * Extend the `data` property of a scenario definition with values from a parent
 * scenario definition. Returns the extended value for `data`.
 *
 * @param parentData - the scenario `data` which is extended by the child
 * scenario
 * @param childData - the scenario `data` which may override values from the
 * parent scenario
 */
// eslint-disable-next-line complexity
export const extendScenarioDefinitionData = (
  parentData: NonNullable<AuthenticationTemplateScenario['data']>,
  childData: NonNullable<AuthenticationTemplateScenario['data']>
) => ({
  ...parentData,
  ...childData,
  ...(parentData.bytecode === undefined && childData.bytecode === undefined
    ? {}
    : {
        bytecode: {
          ...parentData.bytecode,
          ...childData.bytecode,
        },
      }),
  ...(parentData.hdKeys === undefined && childData.hdKeys === undefined
    ? {}
    : {
        hdKeys: {
          ...parentData.hdKeys,
          ...childData.hdKeys,
          ...(parentData.hdKeys?.hdPrivateKeys === undefined &&
          childData.hdKeys?.hdPrivateKeys === undefined
            ? {}
            : {
                hdPrivateKeys: {
                  ...parentData.hdKeys?.hdPrivateKeys,
                  ...childData.hdKeys?.hdPrivateKeys,
                },
              }),
          ...(parentData.hdKeys?.hdPublicKeys === undefined &&
          childData.hdKeys?.hdPublicKeys === undefined
            ? {}
            : {
                hdPublicKeys: {
                  ...parentData.hdKeys?.hdPublicKeys,
                  ...childData.hdKeys?.hdPublicKeys,
                },
              }),
        },
      }),
  ...(parentData.keys === undefined && childData.keys === undefined
    ? {}
    : {
        keys: {
          privateKeys: {
            ...parentData.keys?.privateKeys,
            ...childData.keys?.privateKeys,
          },
        },
      }),
});

/**
 * Extend a child scenario definition with values from a parent scenario
 * definition. Returns the extended values for `data`, `transaction`, and
 * `value`.
 *
 * @param parentScenario - the scenario which is extended by the child scenario
 * @param childScenario - the scenario which may override values from the parent
 * scenario
 */
// eslint-disable-next-line complexity
export const extendScenarioDefinition = <
  ParentScenarioType extends AuthenticationTemplateScenario
>(
  parentScenario: ParentScenarioType,
  childScenario: AuthenticationTemplateScenario
) =>
  ({
    ...(parentScenario.data === undefined && childScenario.data === undefined
      ? {}
      : {
          data: extendScenarioDefinitionData(
            parentScenario.data ?? {},
            childScenario.data ?? {}
          ),
        }),
    ...(parentScenario.transaction === undefined &&
    childScenario.transaction === undefined
      ? {}
      : {
          transaction: {
            ...parentScenario.transaction,
            ...childScenario.transaction,
          },
        }),
    ...(parentScenario.sourceOutputs === undefined &&
    childScenario.sourceOutputs === undefined
      ? {}
      : {
          sourceOutputs:
            childScenario.sourceOutputs ?? parentScenario.sourceOutputs,
        }),
  } as ParentScenarioType extends ExtendedScenarioDefinition
    ? ExtendedScenarioDefinition
    : ScenarioDefinition);

/**
 * Generate the full scenario which is extended by the provided scenario
 * identifier. Scenarios for which `extends` is `undefined` extend the default
 * scenario for the provided compiler configuration.
 *
 * @param scenarioId - the identifier of the scenario for from which to select
 * the extended scenario
 * @param configuration - the compiler configuration from which to generate the
 * extended scenario
 * @param sourceScenarioIds - an array of scenario identifiers indicating the
 * path taken to arrive at the current scenario - used to detect and prevent
 * cycles in extending scenarios (defaults to `[]`)
 */
// eslint-disable-next-line complexity
export const generateExtendedScenario = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations<CompilationContext>,
  CompilationContext
>({
  configuration,
  scenarioId,
  sourceScenarioIds = [],
}: {
  configuration: Configuration;
  scenarioId?: string | undefined;
  sourceScenarioIds?: string[];
}): ExtendedScenarioDefinition | string => {
  if (scenarioId === undefined) {
    return generateDefaultScenarioDefinition<Configuration, CompilationContext>(
      configuration
    );
  }

  if (sourceScenarioIds.includes(scenarioId)) {
    return `Cannot extend scenario "${scenarioId}": scenario "${scenarioId}" extends itself. Scenario inheritance path: ${sourceScenarioIds.join(
      ' → '
    )}`;
  }
  const scenario = configuration.scenarios?.[scenarioId];
  if (scenario === undefined) {
    return `Cannot extend scenario "${scenarioId}": a scenario with the identifier ${scenarioId} is not included in this compiler configuration.`;
  }
  const parentScenario =
    scenario.extends === undefined
      ? generateDefaultScenarioDefinition<Configuration, CompilationContext>(
          configuration
        )
      : generateExtendedScenario<Configuration, CompilationContext>({
          configuration,
          scenarioId: scenario.extends,
          sourceScenarioIds: [...sourceScenarioIds, scenarioId],
        });
  if (typeof parentScenario === 'string') {
    return parentScenario;
  }

  return extendScenarioDefinition(parentScenario, scenario);
};

/**
 * Derive standard `CompilationData` properties from an extended scenario
 * definition.
 * @param definition - a scenario definition which has been extended by the
 * default scenario definition
 */
// eslint-disable-next-line complexity
export const extendedScenarioDefinitionToCompilationData = (
  definition: Required<Pick<ScenarioDefinition, 'data'>> & ScenarioDefinition
): CompilationData => ({
  ...(definition.data.currentBlockHeight === undefined
    ? {}
    : {
        currentBlockHeight: definition.data.currentBlockHeight,
      }),
  ...(definition.data.currentBlockTime === undefined
    ? {}
    : {
        currentBlockTime: definition.data.currentBlockTime,
      }),
  ...(definition.data.hdKeys === undefined
    ? {}
    : {
        hdKeys: {
          ...(definition.data.hdKeys.addressIndex === undefined
            ? {}
            : {
                addressIndex: definition.data.hdKeys.addressIndex,
              }),
          ...(definition.data.hdKeys.hdPrivateKeys !== undefined &&
          Object.keys(definition.data.hdKeys.hdPrivateKeys).length > 0
            ? {
                hdPrivateKeys: definition.data.hdKeys.hdPrivateKeys,
              }
            : {}),
          ...(definition.data.hdKeys.hdPublicKeys === undefined
            ? {}
            : {
                hdPublicKeys: definition.data.hdKeys.hdPublicKeys,
              }),
        },
      }),
  ...(definition.data.keys?.privateKeys !== undefined &&
  Object.keys(definition.data.keys.privateKeys).length > 0
    ? {
        keys: {
          privateKeys: Object.entries(definition.data.keys.privateKeys).reduce(
            (all, [id, hex]) => ({ ...all, [id]: hexToBin(hex) }),
            {}
          ),
        },
      }
    : {}),
});

/**
 * Extend a {@link CompilationData} object with the compiled result of the
 * bytecode scripts provided by an {@link AuthenticationTemplateScenarioData}.
 */
export const extendCompilationDataWithScenarioBytecode = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations<CompilationContext>,
  CompilationContext
>({
  compilationData,
  configuration,
  scenarioDataBytecodeScripts,
}: {
  /**
   * The compilation data to extend.
   */
  compilationData: CompilationData<CompilationContext>;
  /**
   * The compiler configuration in which to compile the scripts.
   */
  configuration: Configuration;
  /**
   * The {@link AuthenticationTemplateScenarioData.bytecode} property.
   */
  scenarioDataBytecodeScripts: NonNullable<
    AuthenticationTemplateScenarioData['bytecode']
  >;
}) => {
  const prefixBytecodeScriptId = (id: string) =>
    `${CompilerDefaults.scenarioBytecodeScriptPrefix}${id}`;
  const bytecodeScripts = Object.entries(scenarioDataBytecodeScripts).reduce<{
    [bytecodeScriptIdentifier: string]: string;
  }>(
    (all, [id, script]) => ({
      ...all,
      [prefixBytecodeScriptId(id)]: script,
    }),
    {}
  );

  const bytecodeScriptExtendedConfiguration: Configuration = {
    ...configuration,
    scripts: {
      ...configuration.scripts,
      ...bytecodeScripts,
    },
  };

  const bytecodeCompilations: (
    | {
        bytecode: Uint8Array;
        id: string;
      }
    | {
        errors: CompilationError[] | [CompilationError];
        id: string;
      }
  )[] = Object.keys(scenarioDataBytecodeScripts).map((id) => {
    const result = compileScriptRaw({
      configuration: bytecodeScriptExtendedConfiguration,
      data: compilationData,
      scriptId: prefixBytecodeScriptId(id),
    });
    if (result.success) {
      return {
        bytecode: result.bytecode,
        id,
      };
    }
    return {
      errors: result.errors,
      id,
    };
  });

  const failedResults = bytecodeCompilations.filter(
    (
      result
    ): result is {
      errors: CompilationError[] | [CompilationError];
      id: string;
    } => 'errors' in result
  );
  if (failedResults.length > 0) {
    return `${failedResults
      .map(
        (result) =>
          `Compilation error while generating bytecode for "${
            result.id
          }": ${stringifyErrors(result.errors)}`
      )
      .join('; ')}`;
  }

  const compiledBytecode = (
    bytecodeCompilations as {
      bytecode: Uint8Array;
      id: string;
    }[]
  ).reduce<{ [fullIdentifier: string]: Uint8Array }>(
    (all, result) => ({ ...all, [result.id]: result.bytecode }),
    {}
  );

  return {
    ...(Object.keys(compiledBytecode).length > 0
      ? { bytecode: compiledBytecode }
      : {}),
    ...compilationData,
  } as CompilationData<CompilationContext>;
};

/**
 * Compile a {@link AuthenticationTemplateScenarioOutput.valueSatoshis},
 * returning the `Uint8Array` result.
 */
export const compileAuthenticationTemplateScenarioValueSatoshis = (
  valueSatoshisDefinition: AuthenticationTemplateScenarioOutput<boolean>['valueSatoshis'] = CompilerDefaults.defaultScenarioOutputValueSatoshis
) =>
  typeof valueSatoshisDefinition === 'string'
    ? hexToBin(valueSatoshisDefinition)
    : bigIntToBinUint64LE(BigInt(valueSatoshisDefinition));

/**
 * Compile an {@link AuthenticationTemplateScenarioBytecode} definition for an
 * {@link AuthenticationTemplateScenario}, returning either a
 * simple `Uint8Array` result or a full CashAssembly {@link CompilationResult}.
 */
// eslint-disable-next-line complexity
export const compileAuthenticationTemplateScenarioBytecode = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations,
  GenerateBytecode extends Compiler<
    CompilationContextBCH,
    Configuration,
    ProgramState
  >['generateBytecode'],
  ProgramState
>({
  bytecodeDefinition,
  configuration,
  defaultOverride,
  extendedScenario,
  generateBytecode,
  lockingOrUnlockingScriptIdUnderTest,
}: {
  bytecodeDefinition: AuthenticationTemplateScenarioBytecode;
  configuration: Configuration;
  extendedScenario: ExtendedScenarioDefinition;
  defaultOverride: AuthenticationTemplateScenarioData;
  generateBytecode: GenerateBytecode;
  lockingOrUnlockingScriptIdUnderTest?: string;
}):
  | CompilationResult<ProgramState>
  | Uint8Array
  | { errors: [{ error: string }]; success: false } => {
  if (typeof bytecodeDefinition === 'string') {
    return hexToBin(bytecodeDefinition);
  }

  const scriptId =
    bytecodeDefinition.script === undefined ||
    Array.isArray(bytecodeDefinition.script)
      ? lockingOrUnlockingScriptIdUnderTest
      : bytecodeDefinition.script;

  /**
   * The script ID to compile. If `undefined`, we are attempting to "copy" the
   * script ID in a scenario generation that does not define a locking or
   * unlocking script under test (e.g. the scenario is only used for debugging
   * values in an editor) – in these cases, simply return an empty `Uint8Array`.
   */
  if (scriptId === undefined) {
    return hexToBin('');
  }

  const overrides = bytecodeDefinition.overrides ?? defaultOverride;
  const overriddenDataDefinition = extendScenarioDefinitionData(
    extendedScenario.data,
    overrides
  );
  const data = extendCompilationDataWithScenarioBytecode({
    compilationData: extendedScenarioDefinitionToCompilationData({
      data: overriddenDataDefinition,
    }),
    configuration,
    scenarioDataBytecodeScripts: overriddenDataDefinition.bytecode ?? {},
  });

  if (typeof data === 'string') {
    const error = `Could not compile scenario "data.bytecode": ${data}`;
    return { errors: [{ error }], success: false };
  }

  return generateBytecode({ data, debug: true, scriptId });
};

/**
 * Generate a scenario given a compiler configuration. If neither `scenarioId`
 * or `unlockingScriptId` are provided, the default scenario for the compiler
 * configuration will be generated.
 *
 * Returns either the full `CompilationData` for the selected scenario or an
 * error message (as a `string`).
 *
 * Note, this method should typically not be used directly, use
 * {@link Compiler.generateScenario} instead.
 */
// eslint-disable-next-line complexity
export const generateScenarioBCH = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations,
  GenerateBytecode extends Compiler<
    CompilationContextBCH,
    Configuration,
    ProgramState
  >['generateBytecode'],
  ProgramState,
  Debug extends boolean
>(
  {
    configuration,
    generateBytecode,
    scenarioId,
    unlockingScriptId,
  }: {
    /**
     * The compiler configuration from which to generate the scenario.
     */
    configuration: Configuration;

    generateBytecode: GenerateBytecode;
    /**
     * The ID of the scenario to generate. If `undefined`, the default scenario.
     */
    scenarioId?: string | undefined;
    /**
     * The ID of the unlocking script under test by this scenario. If
     * `undefined` but required by the scenario, an error will be produced.
     */
    unlockingScriptId?: string | undefined;
  },
  debug?: Debug
):
  | string
  | (Debug extends true
      ? ScenarioGenerationDebuggingResult<ProgramState>
      : Scenario) => {
  const { scenarioDefinition, scenarioName } =
    scenarioId === undefined
      ? { scenarioDefinition: {}, scenarioName: `the default scenario` }
      : {
          scenarioDefinition: configuration.scenarios?.[scenarioId],
          scenarioName: `scenario "${scenarioId}"`,
        };

  if (scenarioDefinition === undefined) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return `Cannot generate ${scenarioName}: a scenario definition with the identifier ${scenarioId!} is not included in this compiler configuration.`;
  }

  const parentScenario = generateExtendedScenario<
    Configuration,
    CompilationContextBCH
  >({ configuration, scenarioId });
  if (typeof parentScenario === 'string') {
    return `Cannot generate ${scenarioName}: ${parentScenario}`;
  }

  const extendedScenario = extendScenarioDefinition(
    parentScenario,
    scenarioDefinition
  );
  const partialCompilationData =
    extendedScenarioDefinitionToCompilationData(extendedScenario);
  const fullCompilationData = extendCompilationDataWithScenarioBytecode({
    compilationData: partialCompilationData,
    configuration,
    scenarioDataBytecodeScripts: extendedScenario.data.bytecode ?? {},
  });

  if (typeof fullCompilationData === 'string') {
    return `Cannot generate ${scenarioName}. ${fullCompilationData}`;
  }

  if (
    extendedScenario.transaction.inputs.length !==
    extendedScenario.sourceOutputs.length
  ) {
    return `Cannot generate ${scenarioName}: could not match source outputs with inputs – "sourceOutputs" must be the same length as "transaction.inputs".`;
  }

  const testedInputs = extendedScenario.transaction.inputs.filter((input) =>
    Array.isArray(input.unlockingBytecode)
  );
  if (testedInputs.length !== 1) {
    return `Cannot generate ${scenarioName}: the specific input under test in this scenario is ambiguous – "transaction.inputs" must include exactly one input which has "unlockingBytecode" set to ["slot"].`;
  }
  const testedInputIndex = extendedScenario.transaction.inputs.findIndex(
    (input) => Array.isArray(input.unlockingBytecode)
  );

  const testedSourceOutputs = extendedScenario.sourceOutputs.filter((output) =>
    Array.isArray(output.lockingBytecode)
  );
  if (testedSourceOutputs.length !== 1) {
    return `Cannot generate ${scenarioName}: the source output unlocked by the input under test in this scenario is ambiguous – "sourceOutputs" must include exactly one output which has "lockingBytecode" set to ["slot"].`;
  }

  if (
    !Array.isArray(
      extendedScenario.sourceOutputs[testedInputIndex].lockingBytecode
    )
  ) {
    return `Cannot generate ${scenarioName}: the source output unlocked by the input under test in this scenario is ambiguous – the ["slot"] in "transaction.inputs" and "sourceOutputs" must be at the same index.`;
  }

  const lockingScriptId =
    unlockingScriptId === undefined
      ? undefined
      : configuration.unlockingScripts?.[unlockingScriptId];
  if (unlockingScriptId !== undefined && lockingScriptId === undefined) {
    return `Cannot generate ${scenarioName} using unlocking script "${unlockingScriptId}": the locking script unlocked by "${unlockingScriptId}" is not provided in this compiler configuration.`;
  }

  const sourceOutputCompilations = extendedScenario.sourceOutputs.map(
    (sourceOutput, index) => {
      const slot = Array.isArray(sourceOutput.lockingBytecode);
      const bytecodeDefinition = slot
        ? lockingScriptId === undefined
          ? (CompilerDefaults.defaultScenarioBytecode as string)
          : { script: lockingScriptId }
        : sourceOutput.lockingBytecode ?? {};
      const defaultOverride = {};
      return {
        compiled: {
          lockingBytecode: compileAuthenticationTemplateScenarioBytecode({
            bytecodeDefinition,
            configuration,
            defaultOverride,
            extendedScenario,
            generateBytecode,
            lockingOrUnlockingScriptIdUnderTest: lockingScriptId,
          }),
          valueSatoshis: compileAuthenticationTemplateScenarioValueSatoshis(
            sourceOutput.valueSatoshis
          ),
        },
        index,
        slot,
        type: 'source output' as const,
      };
    }
  );

  const transactionOutputCompilations =
    extendedScenario.transaction.outputs.map((transactionOutput, index) => {
      const defaultOverride = { hdKeys: { addressIndex: 1 } };
      return {
        compiled: {
          lockingBytecode: compileAuthenticationTemplateScenarioBytecode({
            bytecodeDefinition: transactionOutput.lockingBytecode ?? {},
            configuration,
            defaultOverride,
            extendedScenario,
            generateBytecode,
            lockingOrUnlockingScriptIdUnderTest: lockingScriptId,
          }),
          valueSatoshis: compileAuthenticationTemplateScenarioValueSatoshis(
            transactionOutput.valueSatoshis
          ),
        },
        index,
        type: 'transaction output' as const,
      };
    });

  const transactionInputCompilations = extendedScenario.transaction.inputs.map(
    // eslint-disable-next-line complexity
    (input, index) => {
      const slot = Array.isArray(input.unlockingBytecode);
      const bytecodeDefinition = Array.isArray(input.unlockingBytecode)
        ? unlockingScriptId === undefined
          ? (CompilerDefaults.defaultScenarioBytecode as string)
          : { script: unlockingScriptId }
        : input.unlockingBytecode ?? {};
      const defaultOverride = {};
      return {
        compiled: {
          outpointIndex:
            input.outpointIndex ??
            CompilerDefaults.defaultScenarioInputOutpointIndex,
          outpointTransactionHash: hexToBin(
            input.outpointTransactionHash ??
              CompilerDefaults.defaultScenarioInputOutpointTransactionHash
          ),
          sequenceNumber:
            input.sequenceNumber ??
            CompilerDefaults.defaultScenarioInputSequenceNumber,
          unlockingBytecode: compileAuthenticationTemplateScenarioBytecode({
            bytecodeDefinition,
            configuration,
            defaultOverride,
            extendedScenario,
            generateBytecode,
            lockingOrUnlockingScriptIdUnderTest: unlockingScriptId,
          }),
        },
        index,
        slot,
        type: 'input' as const,
      };
    }
  );

  const lockingCompilation = sourceOutputCompilations.find(
    (compilation) => compilation.slot
  )?.compiled.lockingBytecode as CompilationResult<ProgramState>;
  const unlockingCompilation = transactionInputCompilations.find(
    (compilation) => compilation.slot
  )?.compiled.unlockingBytecode as CompilationResult<ProgramState>;

  const errors = [
    ...sourceOutputCompilations,
    ...transactionInputCompilations,
    ...transactionOutputCompilations,
  ].reduce<string[]>((accumulated, result) => {
    const errorSet =
      'lockingBytecode' in result.compiled
        ? 'errors' in result.compiled.lockingBytecode
          ? result.compiled.lockingBytecode.errors
          : undefined
        : 'errors' in result.compiled.unlockingBytecode
        ? result.compiled.unlockingBytecode.errors
        : undefined;
    if (errorSet === undefined) return accumulated;
    return [
      ...accumulated,
      ...errorSet.map(
        (errorObject) =>
          `Failed compilation of ${result.type} at index ${result.index}: ${errorObject.error}`
      ),
    ];
  }, []);

  if (errors.length > 0) {
    const error = `Cannot generate ${scenarioName}: ${errors.join(' ')}`;
    if (debug === true) {
      return {
        lockingCompilation,
        scenario: error,
        unlockingCompilation,
      } as Debug extends true
        ? ScenarioGenerationDebuggingResult<ProgramState>
        : Scenario;
    }
    return error;
  }
  const sourceOutputCompilationsSuccess =
    sourceOutputCompilations as AuthenticationTemplateScenarioOutputSuccessfulCompilation[];
  const transactionOutputCompilationsSuccess =
    transactionOutputCompilations as AuthenticationTemplateScenarioOutputSuccessfulCompilation[];
  const transactionInputCompilationsSuccess =
    transactionInputCompilations as AuthenticationTemplateScenarioInputSuccessfulCompilation[];

  interface AuthenticationTemplateScenarioOutputSuccessfulCompilation {
    compiled: {
      lockingBytecode: CompilationResultSuccess<ProgramState> | Uint8Array;
      valueSatoshis: Uint8Array;
    };
    index: number;
    slot?: boolean;
    type: string;
  }

  interface AuthenticationTemplateScenarioInputSuccessfulCompilation {
    compiled: {
      outpointIndex: number;
      outpointTransactionHash: Uint8Array;
      sequenceNumber: number;
      unlockingBytecode: CompilationResultSuccess<ProgramState> | Uint8Array;
    };
    index: number;
    slot?: boolean;
    type: string;
  }

  const extractOutput = (
    compilation: AuthenticationTemplateScenarioOutputSuccessfulCompilation
  ) => {
    const { lockingBytecode, valueSatoshis } = compilation.compiled;
    return {
      lockingBytecode:
        'bytecode' in lockingBytecode
          ? lockingBytecode.bytecode
          : lockingBytecode,
      valueSatoshis,
    };
  };

  const sourceOutputs = sourceOutputCompilationsSuccess.map(extractOutput);
  const outputs = transactionOutputCompilationsSuccess.map(extractOutput);
  const inputs = transactionInputCompilationsSuccess.map((compilation) => {
    const {
      outpointIndex,
      outpointTransactionHash,
      sequenceNumber,
      unlockingBytecode,
    } = compilation.compiled;
    return {
      outpointIndex,
      outpointTransactionHash,
      sequenceNumber,
      unlockingBytecode:
        'bytecode' in unlockingBytecode
          ? unlockingBytecode.bytecode
          : unlockingBytecode,
    };
  });

  const scenario: Scenario = {
    data: fullCompilationData,
    program: {
      inputIndex: testedInputIndex,
      sourceOutputs,
      transaction: {
        inputs,
        locktime: extendedScenario.transaction.locktime,
        outputs,
        version: extendedScenario.transaction.version,
      },
    },
  };

  return (
    debug === true
      ? { lockingCompilation, scenario, unlockingCompilation }
      : scenario
  ) as Debug extends true
    ? ScenarioGenerationDebuggingResult<ProgramState>
    : Scenario;
};
