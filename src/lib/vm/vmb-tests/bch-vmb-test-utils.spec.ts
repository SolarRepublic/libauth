import test from 'ava';

import { vmbTestGroupToVmbTests } from '../../lib.js';

/* spell-checker: disable */
test('vmbTestGroupToVmbTests', (t) => {
  t.deepEqual(
    vmbTestGroupToVmbTests([
      'Basic push operations',
      [
        [
          'OP_0',
          'OP_SIZE <0> OP_EQUAL',
          'OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item',
        ],
        [
          'OP_PUSHBYTES_1',
          'OP_SIZE <1> OP_EQUAL',
          'OP_PUSHBYTES_1 with missing bytes',
          ['invalid'],
        ],
        [
          '<0>',
          'OP_DROP OP_TXINPUTCOUNT <1> OP_EQUAL',
          'OP_TXINPUTCOUNT operation exists',
          ['2021_invalid'],
        ],
      ],
    ]),
    [
      [
        [
          'ea2f',
          'Basic push operations: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (nonP2SH)',
          'OP_0',
          'OP_SIZE <0> OP_EQUAL',
          '02000000010000000000000000000000000000000000000000000000000000000000000000000000000100000000000100000000000000000382008700000000',
          '01000000000000000003820087',
          ['2021_valid', '2022_valid'],
        ],
        [
          '5tyh',
          'Basic push operations: OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item (P2SH20)',
          'OP_0',
          'OP_SIZE <0> OP_EQUAL',
          '02000000010000000000000000000000000000000000000000000000000000000000000000000000000500038200870000000001000000000000000017a9146b14122b4b3cb280c9ec66f8e2827cf3384010a38700000000',
          '01000000000000000017a9146b14122b4b3cb280c9ec66f8e2827cf3384010a387',
          ['2021_standard', '2022_standard'],
        ],
      ],
      [
        [
          'wh2p',
          'Basic push operations: OP_PUSHBYTES_1 with missing bytes (nonP2SH)',
          'OP_PUSHBYTES_1',
          'OP_SIZE <1> OP_EQUAL',
          '02000000010000000000000000000000000000000000000000000000000000000000000000000000000101000000000100000000000000000382518700000000',
          '01000000000000000003825187',
          ['2021_invalid', '2022_invalid'],
        ],
        [
          '0xc7',
          'Basic push operations: OP_PUSHBYTES_1 with missing bytes (P2SH20)',
          'OP_PUSHBYTES_1',
          'OP_SIZE <1> OP_EQUAL',
          '02000000010000000000000000000000000000000000000000000000000000000000000000000000000501038251870000000001000000000000000017a914348babd902f9237b6d28ad1ee00bf6941bc9bddc8700000000',
          '01000000000000000017a914348babd902f9237b6d28ad1ee00bf6941bc9bddc87',
          ['2021_invalid', '2022_invalid'],
        ],
      ],
      [
        [
          't8js',
          'Basic push operations: OP_TXINPUTCOUNT operation exists (nonP2SH)',
          '<0>',
          'OP_DROP OP_TXINPUTCOUNT <1> OP_EQUAL',
          '02000000010000000000000000000000000000000000000000000000000000000000000000000000000100000000000100000000000000000475c3518700000000',
          '0100000000000000000475c35187',
          ['2021_invalid', '2022_valid'],
        ],
        [
          'pg7a',
          'Basic push operations: OP_TXINPUTCOUNT operation exists (P2SH20)',
          '<0>',
          'OP_DROP OP_TXINPUTCOUNT <1> OP_EQUAL',
          '020000000100000000000000000000000000000000000000000000000000000000000000000000000006000475c351870000000001000000000000000017a914e57b1d9d4512a857ac3c1623bceacfd2356463d18700000000',
          '01000000000000000017a914e57b1d9d4512a857ac3c1623bceacfd2356463d187',
          ['2021_invalid', '2022_standard'],
        ],
      ],
    ]
  );
});
