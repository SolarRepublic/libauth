import type { CompilationContextBCH, Input, Output } from '../lib';
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
  AuthenticationTemplateScenarioData,
  AuthenticationTemplateScenarioOutput,
  AuthenticationTemplateScenarioTransactionOutput,
  CompilationData,
  CompilationError,
  Scenario,
} from './template';
import {
  CompilerDefaults,
  compileScript,
  compileScriptRaw,
  stringifyErrors,
} from './template.js';

/**
 * The default `lockingBytecode` value for scenario outputs is a new empty
 * object (`{}`).
 */
const defaultScenarioTransactionOutputLockingBytecode = () => ({});

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
 * All scenarios extend the default scenario, so the `data`, `transaction` (and
 * all `transaction` properties), and `sourceOutputs` properties are guaranteed
 * to be defined in an extended scenario definition.
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
    sourceOutputs: [{ lockingBytecode: null }],
    transaction: {
      inputs: [{ unlockingBytecode: null }],
      locktime: CompilerDefaults.defaultScenarioTransactionLocktime as const,
      outputs: [
        { lockingBytecode: defaultScenarioTransactionOutputLockingBytecode() },
      ],
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
      crypto,
      valueMap[entityId],
      assumeValid
    );
    const hdPrivateKey = encodeHdPrivateKey(crypto, {
      network: 'mainnet',
      node: masterNode,
    });

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
 * Extend a `CompilationData` object with the compiled result of the bytecode
 * scripts provided by a `AuthenticationTemplateScenarioData`.
 *
 * @param compilationData - the compilation data to extend
 * @param configuration - the compiler configuration in which to compile the
 * scripts
 * @param scenarioDataBytecodeScripts - the `data.bytecode` property of an
 * `AuthenticationTemplateScenarioData`
 */
export const extendCompilationDataWithScenarioBytecode = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations<CompilationContext>,
  CompilationContext
>({
  compilationData,
  configuration,
  scenarioDataBytecodeScripts,
}: {
  compilationData: CompilationData<CompilationContext>;
  configuration: Configuration;
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
 * Generate a scenario given a compiler configuration. If neither `scenarioId`
 * or `unlockingScriptId` are provided, the default scenario for the compiler
 * configuration will be generated.
 *
 * Returns either the full `CompilationData` for the selected scenario or an
 * error message (as a `string`).
 *
 * @param scenarioId - the ID of the scenario to generate – if `undefined`, the
 * default scenario
 * @param unlockingScriptId - the ID of the unlocking script under test by this
 * scenario – if `undefined` but required by the scenario, an error will be
 * produced
 * @param configuration - the compiler configuration from which to generate the
 * scenario
 */
// eslint-disable-next-line complexity
export const generateScenarioCommon = <
  Configuration extends AnyCompilerConfigurationIgnoreOperations
>({
  configuration,
  scenarioId,
  unlockingScriptId,
}: {
  configuration: Configuration;
  scenarioId?: string | undefined;
  unlockingScriptId?: string | undefined;
}): Scenario | string => {
  const { scenario, scenarioName } =
    scenarioId === undefined
      ? { scenario: {}, scenarioName: `the default scenario` }
      : {
          scenario: configuration.scenarios?.[scenarioId],
          scenarioName: `scenario "${scenarioId}"`,
        };

  if (scenario === undefined) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return `Cannot generate ${scenarioName}: a scenario with the identifier ${scenarioId!} is not included in this compiler configuration.`;
  }

  const parentScenario = generateExtendedScenario<
    Configuration,
    CompilationContextBCH
  >({ configuration, scenarioId });
  if (typeof parentScenario === 'string') {
    return `Cannot generate ${scenarioName}: ${parentScenario}`;
  }

  const extendedScenario = extendScenarioDefinition(parentScenario, scenario);
  const partialCompilationData =
    extendedScenarioDefinitionToCompilationData(extendedScenario);
  const fullCompilationData = extendCompilationDataWithScenarioBytecode({
    compilationData: partialCompilationData,
    configuration,
    scenarioDataBytecodeScripts: extendedScenario.data.bytecode ?? {},
  });

  if (typeof fullCompilationData === 'string') {
    return `Cannot generate ${scenarioName}: ${fullCompilationData}`;
  }

  if (
    extendedScenario.transaction.inputs.length !==
    extendedScenario.sourceOutputs.length
  ) {
    return `Cannot generate ${scenarioName}: could not match source outputs with inputs – "sourceOutputs" must be the same length as "transaction.inputs".`;
  }

  const testedInputs = extendedScenario.transaction.inputs.filter(
    (input) => input.unlockingBytecode === null
  );
  if (testedInputs.length !== 1) {
    return `Cannot generate ${scenarioName}: the specific input under test in this scenario is ambiguous – "transaction.inputs" must include exactly one input which has "unlockingBytecode" set to "null".`;
  }
  const testedInputIndex = extendedScenario.transaction.inputs.findIndex(
    (input) => input.unlockingBytecode === null
  );

  const testedSourceOutputs = extendedScenario.sourceOutputs.filter(
    (output) => output.lockingBytecode === null
  );
  if (testedSourceOutputs.length !== 1) {
    return `Cannot generate ${scenarioName}: the source output unlocked by the input under test in this scenario is ambiguous – "sourceOutputs" must include exactly one output which has "lockingBytecode" set to "null".`;
  }

  if (
    extendedScenario.sourceOutputs[testedInputIndex].lockingBytecode !== null
  ) {
    return `Cannot generate ${scenarioName}: the source output unlocked by the input under test in this scenario is ambiguous – the "null" locking and unlocking bytecode in "transaction.inputs" and "sourceOutputs" must be at the same index.`;
  }

  const outputs = extendedScenario.transaction.outputs.map<
    Required<AuthenticationTemplateScenarioTransactionOutput>
  >((output) => ({
    lockingBytecode:
      output.lockingBytecode ??
      defaultScenarioTransactionOutputLockingBytecode(),
    valueSatoshis:
      output.valueSatoshis ??
      CompilerDefaults.defaultScenarioOutputValueSatoshis,
  }));

  const bytecodeUnderTest = undefined;
  const compileOutput =
    (overrideAddressIndex: boolean) =>
    // eslint-disable-next-line complexity
    (
      output: Required<AuthenticationTemplateScenarioOutput<boolean>>,
      index: number
    ) => {
      const valueSatoshis =
        typeof output.valueSatoshis === 'string'
          ? hexToBin(output.valueSatoshis)
          : bigIntToBinUint64LE(BigInt(output.valueSatoshis));

      if (output.lockingBytecode === null) {
        return { lockingBytecode: bytecodeUnderTest, valueSatoshis };
      }

      if (typeof output.lockingBytecode === 'string') {
        return {
          lockingBytecode: hexToBin(output.lockingBytecode),
          valueSatoshis,
        };
      }

      const specifiedLockingScriptId = output.lockingBytecode.script;
      const impliedLockingScriptId =
        unlockingScriptId === undefined
          ? undefined
          : configuration.unlockingScripts?.[unlockingScriptId];
      const scriptId =
        typeof specifiedLockingScriptId === 'string'
          ? specifiedLockingScriptId
          : impliedLockingScriptId;

      if (scriptId === undefined) {
        if (unlockingScriptId === undefined) {
          return `Cannot generate locking bytecode for output ${index}: this output is set to use the script unlocked by the unlocking script under test, but an unlocking script ID was not provided for scenario generation.`;
        }
        return `Cannot generate locking bytecode for output ${index}: the locking script unlocked by "${unlockingScriptId}" is not provided in this compiler configuration.`;
      }

      const overriddenDataDefinition =
        output.lockingBytecode.overrides === undefined
          ? overrideAddressIndex
            ? extendScenarioDefinitionData(extendedScenario.data, {
                hdKeys: { addressIndex: 1 },
              })
            : undefined
          : extendScenarioDefinitionData(
              extendedScenario.data,
              output.lockingBytecode.overrides
            );

      const overriddenCompilationData =
        overriddenDataDefinition === undefined
          ? undefined
          : extendCompilationDataWithScenarioBytecode({
              compilationData: extendedScenarioDefinitionToCompilationData({
                data: overriddenDataDefinition,
              }),
              configuration,
              scenarioDataBytecodeScripts:
                overriddenDataDefinition.bytecode ?? {},
            });

      if (typeof overriddenCompilationData === 'string') {
        return `Cannot generate locking bytecode for output ${index}: ${overriddenCompilationData}`;
      }

      const data =
        overriddenCompilationData === undefined
          ? fullCompilationData
          : overriddenCompilationData;

      const result = compileScript(scriptId, data, configuration);

      if (!result.success) {
        return `Cannot generate locking bytecode for output ${index}: ${stringifyErrors(
          result.errors
        )}`;
      }

      return { lockingBytecode: result.bytecode, valueSatoshis };
    };

  const compiledTransactionOutputResults = outputs.map<
    Output<Uint8Array | undefined> | string
  >(compileOutput(true));
  const outputCompilationErrors = compiledTransactionOutputResults.filter(
    (result): result is string => typeof result === 'string'
  );
  if (outputCompilationErrors.length > 0) {
    return `Cannot generate ${scenarioName}: ${outputCompilationErrors.join(
      '; '
    )}`;
  }
  const compiledTransactionOutputs =
    compiledTransactionOutputResults as Output[];

  const compiledSourceOutputResults = outputs.map<
    Output<Uint8Array | undefined> | string
  >(compileOutput(false));
  const sourceOutputCompilationErrors = compiledSourceOutputResults.filter(
    (result): result is string => typeof result === 'string'
  );
  if (outputCompilationErrors.length > 0) {
    return `Cannot generate ${scenarioName}: ${sourceOutputCompilationErrors.join(
      '; '
    )}`;
  }
  const compiledSourceOutputs = compiledSourceOutputResults as Output<
    Uint8Array | undefined
  >[];

  const compiledTransactionInputResults =
    extendedScenario.transaction.inputs.map<
      Input<Uint8Array | undefined> | string
      // eslint-disable-next-line complexity
    >((input, index) => {
      const appliedDefaults = {
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
      };

      if (typeof input.unlockingBytecode === 'string') {
        return {
          ...appliedDefaults,
          unlockingBytecode: hexToBin(input.unlockingBytecode),
        };
      }

      if (input.unlockingBytecode === null) {
        return { ...appliedDefaults, unlockingBytecode: bytecodeUnderTest };
      }

      const scriptId =
        input.unlockingBytecode?.script === undefined ||
        input.unlockingBytecode.script === null
          ? unlockingScriptId
          : input.unlockingBytecode.script;

      if (scriptId === undefined) {
        if (unlockingScriptId === undefined) {
          return `Cannot generate unlocking bytecode for input ${index}: this input is set to use the unlocking script under test, but an unlocking script ID was not provided for scenario generation.`;
        }
        return `Cannot generate unlocking bytecode for input ${index}: the unlocking script "${unlockingScriptId}" is not provided in this compiler configuration.`;
      }

      const overriddenDataDefinition =
        input.unlockingBytecode?.overrides === undefined
          ? undefined
          : extendScenarioDefinitionData(
              extendedScenario.data,
              input.unlockingBytecode.overrides
            );

      const overriddenCompilationData =
        overriddenDataDefinition === undefined
          ? undefined
          : extendCompilationDataWithScenarioBytecode({
              compilationData: extendedScenarioDefinitionToCompilationData({
                data: overriddenDataDefinition,
              }),
              configuration,
              scenarioDataBytecodeScripts:
                overriddenDataDefinition.bytecode ?? {},
            });

      if (typeof overriddenCompilationData === 'string') {
        return `Cannot generate unlocking bytecode for input ${index}: ${overriddenCompilationData}`;
      }

      const data =
        overriddenCompilationData === undefined
          ? fullCompilationData
          : overriddenCompilationData;

      const result = compileScript(scriptId, data, configuration);

      if (!result.success) {
        return `Cannot generate unlocking bytecode for input ${index}: ${stringifyErrors(
          result.errors
        )}`;
      }
      return { ...appliedDefaults, unlockingBytecode: result.bytecode };
    });

  const inputCompilationErrors = compiledTransactionInputResults.filter(
    (result): result is string => typeof result === 'string'
  );
  if (inputCompilationErrors.length > 0) {
    return `Cannot generate ${scenarioName}: ${inputCompilationErrors.join(
      '; '
    )}`;
  }
  const compiledTransactionInputs = compiledTransactionInputResults as Input<
    Uint8Array | undefined
  >[];

  return {
    data: fullCompilationData,
    program: {
      inputIndex: testedInputIndex,
      sourceOutputs: compiledSourceOutputs,
      transaction: {
        inputs: compiledTransactionInputs,
        locktime: extendedScenario.transaction.locktime,
        outputs: compiledTransactionOutputs,
        version: extendedScenario.transaction.version,
      },
    },
  };
};
