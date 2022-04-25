/**
 * This script generates all bch_vmb_tests, run it with: `yarn gen:tests`.
 */
// import { mkdirSync } from 'node:fs';

import { bchVmbTests } from '../../lib.js';

/**
 * Script accepts one argument: an `outputDir` to which all generated files will
 * be saved.
 */
const [, , outputDir] = process.argv;

// const path = new URL(outputDir, import.meta.url);

// eslint-disable-next-line functional/no-expression-statement, no-console
console.log(import.meta.url, ',', outputDir);

// eslint-disable-next-line functional/no-expression-statement, no-console
console.log(bchVmbTests);
