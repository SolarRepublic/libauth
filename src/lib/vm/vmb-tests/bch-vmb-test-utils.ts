/**
 * This script generates all bch_vmb_tests, run it with: `yarn gen:tests`.
 */
import { sha256 } from '../../crypto/default-crypto-instances.js';
import {
  authenticationTemplateToCompilerConfiguration,
  binToHex,
  encodeBech32,
  encodeOutputsForTransaction,
  encodeTransaction,
  flattenBinArray,
  regroupBits,
} from '../../lib.js';
import { createCompilerBCH } from '../../template/template.js';

import type {
  VmbTestDefinition,
  VmbTestDefinitionGroup,
} from './bch-vmb-tests.js';

export type VmbTest = [
  shortId: string,
  testDescription: string,
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  expectedBehaviorLabels: VmbTestDefinition[2],
  unlockingScript: string,
  redeemOrLockingScript: string,
  testTransactionHex: string,
  sourceOutputsHex: string,
  /**
   * This isn't required for testing (implementations should always validate the
   * full test transaction), but it can allow downstream applications to
   * identify which source output/transaction input index is the focus of each
   * test. This is likely useful for VM documentation projects that extract
   * usage examples from vmb tests.
   *
   * This field is left undefined for `inputIndex`s of `0` (the default).
   */
  inputIndex?: number
];

/**
 * Short IDs use bech32 encoding, so birthday collision probability is approx.
 * `Math.sqrt(2 * (32 ** defaultShortIdLength))`.
 */
const defaultShortIdLength = 5;

// eslint-disable-next-line complexity
export const vmbTestDefinitionToVmbTests = (
  testDefinition: VmbTestDefinition,
  groupName = '',
  shortIdLength = defaultShortIdLength
): VmbTest[] | string => {
  const [
    unlockingScript,
    redeemOrLockingScript,
    expectedBehaviorLabels,
    testDescription,
    otherProperties,
  ] = testDefinition;

  const scenarioOverride = otherProperties?.scenario;
  const includeNonP2sh = otherProperties?.nonP2sh !== true;
  const includeP2sh20 = otherProperties?.p2sh20 !== false;
  const overrideScenarioId = 'test';

  const configuration = authenticationTemplateToCompilerConfiguration({
    entities: { tester: { variables: { key1: { type: 'HdKey' } } } },
    scripts: {
      lockP2sh20: {
        lockingType: 'p2sh20',
        script: redeemOrLockingScript,
      },
      lockStandard: {
        lockingType: 'standard',
        script: redeemOrLockingScript,
      },
      unlockP2sh20: {
        script: unlockingScript,
        unlocks: 'lockP2sh20',
      },
      unlockStandard: {
        script: unlockingScript,
        unlocks: 'lockStandard',
      },
    },
    ...(scenarioOverride === undefined
      ? {}
      : {
          scenarios: {
            [overrideScenarioId]: scenarioOverride,
          },
        }),
    supported: ['BCH_2022_05'],
    version: 0,
  });
  const compiler = createCompilerBCH(configuration);

  const scenarioId =
    scenarioOverride === undefined ? undefined : overrideScenarioId;

  const generateTest = (type: '(P2SH20)' | '(raw)') => {
    const description = `${groupName}: ${testDescription} ${type}`;
    const result = compiler.generateScenario({
      debug: true,
      scenarioId,
      unlockingScriptId: {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        '(P2SH20)': 'unlockP2sh20',
        // eslint-disable-next-line @typescript-eslint/naming-convention
        '(raw)': 'unlockStandard',
      }[type],
    });
    if (typeof result === 'string') {
      return `Error while generating "${description}" - ${result}`;
    }
    if (typeof result.scenario === 'string') {
      return `Error while generating "${description}" - ${result.scenario}`;
    }
    const encodedTx = encodeTransaction(result.scenario.program.transaction);
    const encodedSourceOutputs = encodeOutputsForTransaction(
      result.scenario.program.sourceOutputs
    );
    const shortId = encodeBech32(
      regroupBits({
        bin: sha256.hash(flattenBinArray([encodedTx, encodedSourceOutputs])),
        resultWordLength: 5,
        sourceWordLength: 8,
      }) as number[]
    ).slice(0, shortIdLength);

    return [
      shortId,
      description,
      expectedBehaviorLabels,
      unlockingScript,
      redeemOrLockingScript,
      binToHex(encodedTx),
      binToHex(encodedSourceOutputs),
      ...(result.scenario.program.inputIndex === 0
        ? []
        : [result.scenario.program.inputIndex]),
    ] as VmbTest;
  };

  const results = [
    ...(includeNonP2sh ? [generateTest('(raw)')] : []),
    ...(includeP2sh20 ? [generateTest('(P2SH20)')] : []),
  ];

  if (results.some((result) => typeof result === 'string')) {
    return `Failed to generate VMB tests: ${results
      .filter((result) => typeof result === 'string')
      .join('; ')}`;
  }
  return results as VmbTest[];
};

export const vmbTestGroupToVmbTests = (testGroup: VmbTestDefinitionGroup) =>
  testGroup[1].map((testDefinition) =>
    vmbTestDefinitionToVmbTests(testDefinition, testGroup[0])
  );
