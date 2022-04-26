/**
 * See the [Libauth VMB Tests Readme](./readme.md) for background information on
 * VMB tests.
 *
 * Below is the source data structure used to generate the Libauth Bitcoin Cash
 * (BCH) Virtual Machine Bytecode (VMB) tests (`bch_vmb_tests.json` and all
 * `bch_vmb_tests_*.json` files). Compiling from this file allows us to easily
 * 1) validate the data structure, and 2) reproducibly generate artifacts like
 * public keys, hashes, and signatures.
 *
 * To add tests to this file:
 *  1. Clone the Libauth repo and install dependencies using `yarn install`.
 *  2. Add the new tests below.
 *  3. Run `yarn gen:tests` to regenerate all test vectors.
 *  5. Run `yarn test` to ensure everything is working, then send your PR.
 */

import type { VmbTestDefinitionGroup } from './bch-vmb-test-utils.js';
import { vmbTestGroupToVmbTests } from './bch-vmb-test-utils.js';

/**
 * The source data structure used to generate the Libauth BCH VMB test
 * vectors (`bch_vmb_tests.json` and all `bch_vmb_*_tx.json` files).
 */
export const vmbTestDefinitionsBCH: VmbTestDefinitionGroup[] = [
  [
    'Basic push operations',
    [
      ['OP_0', 'OP_SIZE <0> OP_EQUAL OP_NIP', 'OP_0 (A.K.A. OP_PUSHBYTES_0, OP_FALSE): zero is represented by an empty stack item'],
      ['OP_PUSHBYTES_1 0x00', 'OP_SIZE <1> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_1'],
      ['OP_PUSHBYTES_2 0x0000', 'OP_SIZE <2> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_2'],
      ['OP_PUSHBYTES_3 0x000000', 'OP_SIZE <3> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_3'],
      ['OP_PUSHBYTES_4 0x00000000', 'OP_SIZE <4> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_4'],
      ['OP_PUSHBYTES_5 0x0000000000', 'OP_SIZE <5> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_5'],
      ['OP_PUSHBYTES_6 0x000000000000', 'OP_SIZE <6> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_6'],
      ['OP_PUSHBYTES_7 0x00000000000000', 'OP_SIZE <7> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_7'],
      ['OP_PUSHBYTES_8 0x0000000000000000', 'OP_SIZE <8> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_8'],
      ['OP_PUSHBYTES_9 0x000000000000000000', 'OP_SIZE <9> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_9'],
      ['OP_PUSHBYTES_10 0x00000000000000000000', 'OP_SIZE <10> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_10'],
      ['OP_PUSHBYTES_11 0x0000000000000000000000', 'OP_SIZE <11> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_11'],
      ['OP_PUSHBYTES_12 0x000000000000000000000000', 'OP_SIZE <12> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_12'],
      ['OP_PUSHBYTES_13 0x00000000000000000000000000', 'OP_SIZE <13> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_13'],
      ['OP_PUSHBYTES_14 0x0000000000000000000000000000', 'OP_SIZE <14> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_14'],
      ['OP_PUSHBYTES_15 0x000000000000000000000000000000', 'OP_SIZE <15> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_15'],
      ['OP_PUSHBYTES_16 0x00000000000000000000000000000000', 'OP_SIZE <16> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_16'],
      ['OP_PUSHBYTES_17 0x0000000000000000000000000000000000', 'OP_SIZE <17> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_17'],
      ['OP_PUSHBYTES_18 0x000000000000000000000000000000000000', 'OP_SIZE <18> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_18'],
      ['OP_PUSHBYTES_19 0x00000000000000000000000000000000000000', 'OP_SIZE <19> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_19'],
      ['OP_PUSHBYTES_20 0x0000000000000000000000000000000000000000', 'OP_SIZE <20> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_20'],
      ['OP_PUSHBYTES_21 0x000000000000000000000000000000000000000000', 'OP_SIZE <21> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_21'],
      ['OP_PUSHBYTES_22 0x00000000000000000000000000000000000000000000', 'OP_SIZE <22> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_22'],
      ['OP_PUSHBYTES_23 0x0000000000000000000000000000000000000000000000', 'OP_SIZE <23> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_23'],
      ['OP_PUSHBYTES_24 0x000000000000000000000000000000000000000000000000', 'OP_SIZE <24> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_24'],
      ['OP_PUSHBYTES_25 0x00000000000000000000000000000000000000000000000000', 'OP_SIZE <25> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_25'],
      ['OP_PUSHBYTES_26 0x0000000000000000000000000000000000000000000000000000', 'OP_SIZE <26> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_26'],
      ['OP_PUSHBYTES_27 0x000000000000000000000000000000000000000000000000000000', 'OP_SIZE <27> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_27'],
      ['OP_PUSHBYTES_28 0x00000000000000000000000000000000000000000000000000000000', 'OP_SIZE <28> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_28'],
      ['OP_PUSHBYTES_29 0x0000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <29> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_29'],
      ['OP_PUSHBYTES_30 0x000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <30> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_30'],
      ['OP_PUSHBYTES_31 0x00000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <31> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_31'],
      ['OP_PUSHBYTES_32 0x0000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <32> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_32'],
      ['OP_PUSHBYTES_33 0x000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <33> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_33'],
      ['OP_PUSHBYTES_34 0x00000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <34> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_34'],
      ['OP_PUSHBYTES_35 0x0000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <35> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_35'],
      ['OP_PUSHBYTES_36 0x000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <36> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_36'],
      ['OP_PUSHBYTES_37 0x00000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <37> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_37'],
      ['OP_PUSHBYTES_38 0x0000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <38> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_38'],
      ['OP_PUSHBYTES_39 0x000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <39> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_39'],
      ['OP_PUSHBYTES_40 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <40> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_40'],
      ['OP_PUSHBYTES_41 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <41> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_41'],
      ['OP_PUSHBYTES_42 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <42> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_42'],
      ['OP_PUSHBYTES_43 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <43> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_43'],
      ['OP_PUSHBYTES_44 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <44> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_44'],
      ['OP_PUSHBYTES_45 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <45> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_45'],
      ['OP_PUSHBYTES_46 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <46> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_46'],
      ['OP_PUSHBYTES_47 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <47> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_47'],
      ['OP_PUSHBYTES_48 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <48> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_48'],
      ['OP_PUSHBYTES_49 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <49> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_49'],
      ['OP_PUSHBYTES_50 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <50> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_50'],
      ['OP_PUSHBYTES_51 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <51> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_51'],
      ['OP_PUSHBYTES_52 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <52> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_52'],
      ['OP_PUSHBYTES_53 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <53> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_53'],
      ['OP_PUSHBYTES_54 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <54> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_54'],
      ['OP_PUSHBYTES_55 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <55> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_55'],
      ['OP_PUSHBYTES_56 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <56> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_56'],
      ['OP_PUSHBYTES_57 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <57> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_57'],
      ['OP_PUSHBYTES_58 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <58> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_58'],
      ['OP_PUSHBYTES_59 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <59> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_59'],
      ['OP_PUSHBYTES_60 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <60> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_60'],
      ['OP_PUSHBYTES_61 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <61> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_61'],
      ['OP_PUSHBYTES_62 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <62> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_62'],
      ['OP_PUSHBYTES_63 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <63> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_63'],
      ['OP_PUSHBYTES_64 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <64> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_64'],
      ['OP_PUSHBYTES_65 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <65> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_65'],
      ['OP_PUSHBYTES_66 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <66> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_66'],
      ['OP_PUSHBYTES_67 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <67> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_67'],
      ['OP_PUSHBYTES_68 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <68> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_68'],
      ['OP_PUSHBYTES_69 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <69> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_69'],
      ['OP_PUSHBYTES_70 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <70> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_70'],
      ['OP_PUSHBYTES_71 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <71> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_71'],
      ['OP_PUSHBYTES_72 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <72> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_72'],
      ['OP_PUSHBYTES_73 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <73> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_73'],
      ['OP_PUSHBYTES_74 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <74> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_74'],
      ['OP_PUSHBYTES_75 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'OP_SIZE <75> OP_EQUAL OP_NIP', 'OP_PUSHBYTES_75'],
      ['OP_PUSHBYTES_1', 'OP_SIZE <1> OP_EQUAL', 'OP_PUSHBYTES_1 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_2 0x00', 'OP_SIZE <2> OP_EQUAL', 'OP_PUSHBYTES_2 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_3 0x00', 'OP_SIZE <3> OP_EQUAL', 'OP_PUSHBYTES_3 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_4 0x00', 'OP_SIZE <4> OP_EQUAL', 'OP_PUSHBYTES_4 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_5 0x00', 'OP_SIZE <5> OP_EQUAL', 'OP_PUSHBYTES_5 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_6 0x00', 'OP_SIZE <6> OP_EQUAL', 'OP_PUSHBYTES_6 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_7 0x00', 'OP_SIZE <7> OP_EQUAL', 'OP_PUSHBYTES_7 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_8 0x00', 'OP_SIZE <8> OP_EQUAL', 'OP_PUSHBYTES_8 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_9 0x00', 'OP_SIZE <9> OP_EQUAL', 'OP_PUSHBYTES_9 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_10 0x00', 'OP_SIZE <10> OP_EQUAL', 'OP_PUSHBYTES_10 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_11 0x00', 'OP_SIZE <11> OP_EQUAL', 'OP_PUSHBYTES_11 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_12 0x00', 'OP_SIZE <12> OP_EQUAL', 'OP_PUSHBYTES_12 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_13 0x00', 'OP_SIZE <13> OP_EQUAL', 'OP_PUSHBYTES_13 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_14 0x00', 'OP_SIZE <14> OP_EQUAL', 'OP_PUSHBYTES_14 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_15 0x00', 'OP_SIZE <15> OP_EQUAL', 'OP_PUSHBYTES_15 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_16 0x00', 'OP_SIZE <16> OP_EQUAL', 'OP_PUSHBYTES_16 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_17 0x00', 'OP_SIZE <17> OP_EQUAL', 'OP_PUSHBYTES_17 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_18 0x00', 'OP_SIZE <18> OP_EQUAL', 'OP_PUSHBYTES_18 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_19 0x00', 'OP_SIZE <19> OP_EQUAL', 'OP_PUSHBYTES_19 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_20 0x00', 'OP_SIZE <20> OP_EQUAL', 'OP_PUSHBYTES_20 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_21 0x00', 'OP_SIZE <21> OP_EQUAL', 'OP_PUSHBYTES_21 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_22 0x00', 'OP_SIZE <22> OP_EQUAL', 'OP_PUSHBYTES_22 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_23 0x00', 'OP_SIZE <23> OP_EQUAL', 'OP_PUSHBYTES_23 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_24 0x00', 'OP_SIZE <24> OP_EQUAL', 'OP_PUSHBYTES_24 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_25 0x00', 'OP_SIZE <25> OP_EQUAL', 'OP_PUSHBYTES_25 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_26 0x00', 'OP_SIZE <26> OP_EQUAL', 'OP_PUSHBYTES_26 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_27 0x00', 'OP_SIZE <27> OP_EQUAL', 'OP_PUSHBYTES_27 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_28 0x00', 'OP_SIZE <28> OP_EQUAL', 'OP_PUSHBYTES_28 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_29 0x00', 'OP_SIZE <29> OP_EQUAL', 'OP_PUSHBYTES_29 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_30 0x00', 'OP_SIZE <30> OP_EQUAL', 'OP_PUSHBYTES_30 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_31 0x00', 'OP_SIZE <31> OP_EQUAL', 'OP_PUSHBYTES_31 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_32 0x00', 'OP_SIZE <32> OP_EQUAL', 'OP_PUSHBYTES_32 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_33 0x00', 'OP_SIZE <33> OP_EQUAL', 'OP_PUSHBYTES_33 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_34 0x00', 'OP_SIZE <34> OP_EQUAL', 'OP_PUSHBYTES_34 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_35 0x00', 'OP_SIZE <35> OP_EQUAL', 'OP_PUSHBYTES_35 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_36 0x00', 'OP_SIZE <36> OP_EQUAL', 'OP_PUSHBYTES_36 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_37 0x00', 'OP_SIZE <37> OP_EQUAL', 'OP_PUSHBYTES_37 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_38 0x00', 'OP_SIZE <38> OP_EQUAL', 'OP_PUSHBYTES_38 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_39 0x00', 'OP_SIZE <39> OP_EQUAL', 'OP_PUSHBYTES_39 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_40 0x00', 'OP_SIZE <40> OP_EQUAL', 'OP_PUSHBYTES_40 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_41 0x00', 'OP_SIZE <41> OP_EQUAL', 'OP_PUSHBYTES_41 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_42 0x00', 'OP_SIZE <42> OP_EQUAL', 'OP_PUSHBYTES_42 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_43 0x00', 'OP_SIZE <43> OP_EQUAL', 'OP_PUSHBYTES_43 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_44 0x00', 'OP_SIZE <44> OP_EQUAL', 'OP_PUSHBYTES_44 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_45 0x00', 'OP_SIZE <45> OP_EQUAL', 'OP_PUSHBYTES_45 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_46 0x00', 'OP_SIZE <46> OP_EQUAL', 'OP_PUSHBYTES_46 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_47 0x00', 'OP_SIZE <47> OP_EQUAL', 'OP_PUSHBYTES_47 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_48 0x00', 'OP_SIZE <48> OP_EQUAL', 'OP_PUSHBYTES_48 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_49 0x00', 'OP_SIZE <49> OP_EQUAL', 'OP_PUSHBYTES_49 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_50 0x00', 'OP_SIZE <50> OP_EQUAL', 'OP_PUSHBYTES_50 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_51 0x00', 'OP_SIZE <51> OP_EQUAL', 'OP_PUSHBYTES_51 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_52 0x00', 'OP_SIZE <52> OP_EQUAL', 'OP_PUSHBYTES_52 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_53 0x00', 'OP_SIZE <53> OP_EQUAL', 'OP_PUSHBYTES_53 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_54 0x00', 'OP_SIZE <54> OP_EQUAL', 'OP_PUSHBYTES_54 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_55 0x00', 'OP_SIZE <55> OP_EQUAL', 'OP_PUSHBYTES_55 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_56 0x00', 'OP_SIZE <56> OP_EQUAL', 'OP_PUSHBYTES_56 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_57 0x00', 'OP_SIZE <57> OP_EQUAL', 'OP_PUSHBYTES_57 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_58 0x00', 'OP_SIZE <58> OP_EQUAL', 'OP_PUSHBYTES_58 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_59 0x00', 'OP_SIZE <59> OP_EQUAL', 'OP_PUSHBYTES_59 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_60 0x00', 'OP_SIZE <60> OP_EQUAL', 'OP_PUSHBYTES_60 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_61 0x00', 'OP_SIZE <61> OP_EQUAL', 'OP_PUSHBYTES_61 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_62 0x00', 'OP_SIZE <62> OP_EQUAL', 'OP_PUSHBYTES_62 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_63 0x00', 'OP_SIZE <63> OP_EQUAL', 'OP_PUSHBYTES_63 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_64 0x00', 'OP_SIZE <64> OP_EQUAL', 'OP_PUSHBYTES_64 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_65 0x00', 'OP_SIZE <65> OP_EQUAL', 'OP_PUSHBYTES_65 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_66 0x00', 'OP_SIZE <66> OP_EQUAL', 'OP_PUSHBYTES_66 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_67 0x00', 'OP_SIZE <67> OP_EQUAL', 'OP_PUSHBYTES_67 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_68 0x00', 'OP_SIZE <68> OP_EQUAL', 'OP_PUSHBYTES_68 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_69 0x00', 'OP_SIZE <69> OP_EQUAL', 'OP_PUSHBYTES_69 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_70 0x00', 'OP_SIZE <70> OP_EQUAL', 'OP_PUSHBYTES_70 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_71 0x00', 'OP_SIZE <71> OP_EQUAL', 'OP_PUSHBYTES_71 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_72 0x00', 'OP_SIZE <72> OP_EQUAL', 'OP_PUSHBYTES_72 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_73 0x00', 'OP_SIZE <73> OP_EQUAL', 'OP_PUSHBYTES_73 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_74 0x00', 'OP_SIZE <74> OP_EQUAL', 'OP_PUSHBYTES_74 with missing bytes', ['invalid']],
      ['OP_PUSHBYTES_75 0x00', 'OP_SIZE <75> OP_EQUAL', 'OP_PUSHBYTES_75 with missing bytes', ['invalid']],
    ],
  ],
  [
    'push number operations (OP_1NEGATE-OP_16)',
    [
      ['OP_1NEGATE', '<-1 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_1NEGATE pushes 0x81.'],
      ['OP_0', '<0x00> OP_CAT <0x00> OP_EQUAL', 'OP_0 pushes an empty stack item.'],
      ['OP_1', '<1 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_1 pushes 0x01.'],
      ['OP_2', '<2 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_2 pushes 0x02.'],
      ['OP_3', '<3 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_3 pushes 0x03.'],
      ['OP_4', '<4 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_4 pushes 0x04.'],
      ['OP_5', '<5 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_5 pushes 0x05.'],
      ['OP_6', '<6 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_6 pushes 0x06.'],
      ['OP_7', '<7 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_7 pushes 0x07.'],
      ['OP_8', '<8 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_8 pushes 0x08.'],
      ['OP_9', '<9 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_9 pushes 0x09.'],
      ['OP_10', '<10 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_10 pushes 0x0a.'],
      ['OP_11', '<11 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_11 pushes 0x0b.'],
      ['OP_12', '<12 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_12 pushes 0x0c.'],
      ['OP_13', '<13 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_13 pushes 0x0d.'],
      ['OP_14', '<14 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_14 pushes 0x0e.'],
      ['OP_15', '<15 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_15 pushes 0x0f.'],
      ['OP_16', '<16 0x00> <1> OP_SPLIT OP_DROP OP_EQUAL', 'OP_16 pushes 0x10.'],
    ],
  ],
];

export const vmbTestsBCH = vmbTestDefinitionsBCH.map(vmbTestGroupToVmbTests);
