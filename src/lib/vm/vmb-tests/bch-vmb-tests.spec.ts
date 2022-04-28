import test from 'ava';

import type { AuthenticationVirtualMachineBCH, VmbTest } from '../../lib';
import {
  decodeTransactionOutputsUnsafe,
  decodeTransactionUnsafeBCH,
  hexToBin,
  instantiateVirtualMachineBCH2021,
  instantiateVirtualMachineBCH2022,
  stringify,
  vmbTestsBCH,
} from '../../lib.js';

/* eslint-disable import/no-restricted-paths, import/no-internal-modules */
import vmbTestsBCHJson from './generated/bch/bch_vmb_tests.json' assert { type: 'json' };
import vmbTestsBCH2021InvalidJson from './generated/bch/bch_vmb_tests_2021_invalid.json' assert { type: 'json' };
import vmbTestsBCH2021StandardJson from './generated/bch/bch_vmb_tests_2021_standard.json' assert { type: 'json' };
import vmbTestsBCH2021ValidJson from './generated/bch/bch_vmb_tests_2021_valid.json' assert { type: 'json' };
import vmbTestsBCH2022InvalidJson from './generated/bch/bch_vmb_tests_2022_invalid.json' assert { type: 'json' };
import vmbTestsBCH2022StandardJson from './generated/bch/bch_vmb_tests_2022_standard.json' assert { type: 'json' };
import vmbTestsBCH2022ValidJson from './generated/bch/bch_vmb_tests_2022_valid.json' assert { type: 'json' };

/* eslint-enable import/no-restricted-paths, import/no-internal-modules */

test('bch_vmb_tests.json is up to date and contains no test ID collisions', (t) => {
  const testGroupsAndTypes = 2;
  const allTestCases = vmbTestsBCH.flat(testGroupsAndTypes);
  t.deepEqual(
    allTestCases,
    vmbTestsBCHJson,
    'New test definitions were added to `bch-vmb.tests.ts`, but the generated tests were not updated. Run "yarn gen:vmb-tests" to correct this issue. (Note: tsc watch tasks don\'t always update cached JSON imports when the source file changes. You may need to restart tsc to clear this error after re-generating tests.)'
  );

  const testCaseIds = allTestCases.map((testCase) => testCase[0]);
  const firstDuplicate = testCaseIds.find(
    (id, index) => testCaseIds.lastIndexOf(id) !== index
  );
  const noDuplicates = '✅ No duplicate short IDs';
  const duplicateStatus =
    firstDuplicate === undefined
      ? noDuplicates
      : `Duplicate short ID found: ${firstDuplicate}`;
  t.is(
    duplicateStatus,
    noDuplicates,
    `Multiple VMB test vectors share a short ID. Either increase the short ID length, or tweak one of the test definitions to eliminate the collision.`
  );
});

const testVm = ({
  fails,
  succeeds,
  vm,
  vmName,
}: {
  vmName: string;
  succeeds: VmbTest[][];
  fails: VmbTest[][];
  vm: AuthenticationVirtualMachineBCH;
}) => {
  const runCase = test.macro({
    exec: (t, testCase: VmbTest, expectedToSucceed: boolean) => {
      const [
        ,
        ,
        unlockingAsm,
        lockingAsm,
        txHex,
        sourceOutputsHex,
        inputIndex,
      ] = testCase;
      const transaction = decodeTransactionUnsafeBCH(hexToBin(txHex));
      const { outputs: sourceOutputs } = decodeTransactionOutputsUnsafe(
        hexToBin(sourceOutputsHex),
        0
      );
      const result = vm.verify({ sourceOutputs, transaction });
      const logDebugInfo = () => {
        t.log(`unlockingAsm: ${unlockingAsm}`);
        t.log(`lockingAsm: ${lockingAsm}`);
        const debugResult = vm.debug({
          inputIndex: inputIndex ?? 0,
          sourceOutputs,
          transaction,
        });
        t.log(stringify(debugResult));
      };
      if (expectedToSucceed && typeof result === 'string') {
        logDebugInfo();
        t.fail(
          `This VMB test is expected to succeed but failed. Error: ${result}`
        );
        return;
      }
      if (!expectedToSucceed && typeof result !== 'string') {
        logDebugInfo();
        t.fail(`This VMB test is expected to fail but succeeded.`);
        return;
      }
      t.pass();
    },
    title: (
      // eslint-disable-next-line @typescript-eslint/default-param-last
      caseNumberOfCaseCount = '(unknown/unknown)',
      [shortId, description]
    ) =>
      `[vmb_tests] [${vmName}] ${shortId} ${caseNumberOfCaseCount}: ${description}`,
  });
  succeeds.flat(1).forEach((testCase, index, all) => {
    test(`(${index}/${all.length})`, runCase, testCase, true);
  });
  fails.flat(1).forEach((testCase, index, all) => {
    test(`(${index}/${all.length})`, runCase, testCase, false);
  });
};

testVm({
  fails: [
    vmbTestsBCH2021InvalidJson as VmbTest[],
    vmbTestsBCH2021ValidJson as VmbTest[],
  ],
  succeeds: [vmbTestsBCH2021StandardJson as VmbTest[]],
  vm: instantiateVirtualMachineBCH2021(true),
  vmName: 'BCH2021 (standard)',
});

testVm({
  fails: [vmbTestsBCH2021InvalidJson as VmbTest[]],
  succeeds: [
    vmbTestsBCH2021StandardJson as VmbTest[],
    vmbTestsBCH2021ValidJson as VmbTest[],
  ],
  vm: instantiateVirtualMachineBCH2021(false),
  vmName: 'BCH2021 (non-standard)',
});

testVm({
  fails: [
    vmbTestsBCH2022InvalidJson as VmbTest[],
    vmbTestsBCH2022ValidJson as VmbTest[],
  ],
  succeeds: [vmbTestsBCH2022StandardJson as VmbTest[]],
  vm: instantiateVirtualMachineBCH2022(true),
  vmName: 'BCH2022 (standard)',
});

testVm({
  fails: [vmbTestsBCH2022InvalidJson as VmbTest[]],
  succeeds: [
    vmbTestsBCH2022StandardJson as VmbTest[],
    vmbTestsBCH2022ValidJson as VmbTest[],
  ],
  vm: instantiateVirtualMachineBCH2022(false),
  vmName: 'BCH2022 (non-standard)',
});

test.todo('test CHIP limits VM');
