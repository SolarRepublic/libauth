import test from 'ava';

import { vmbTestGroupToVmbTests } from './vmb-tests.js';

/* spell-checker: disable */
test('vmbTestGroupToVmbTests', (t) => {
  const tests = vmbTestGroupToVmbTests([
    'Basic push operations',
    [
      [
        'OP_0',
        'OP_SIZE <0> OP_EQUAL',
        ['standard'],
        'OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item',
      ],
    ],
  ]);
  t.deepEqual(tests, [
    [
      [
        'ea2f0',
        'Basic push operations: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (raw)',
        ['standard'],
        'OP_0',
        'OP_SIZE <0> OP_EQUAL',
        '02000000010000000000000000000000000000000000000000000000000000000000000000000000000100000000000100000000000000000382008700000000',
        '01000000000000000003820087',
      ],
      [
        '5tyhp',
        'Basic push operations: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (P2SH20)',
        ['standard'],
        'OP_0',
        'OP_SIZE <0> OP_EQUAL',
        '02000000010000000000000000000000000000000000000000000000000000000000000000000000000500038200870000000001000000000000000017a9146b14122b4b3cb280c9ec66f8e2827cf3384010a38700000000',
        '01000000000000000017a9146b14122b4b3cb280c9ec66f8e2827cf3384010a387',
      ],
    ],
  ]);
});
