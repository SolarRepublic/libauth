/**
 * Libauth is designed to simultaneously support multiple chains/versions of
 * bitcoin without patches to the Libauth codebase. As such, Libauth can
 * potentially include support for multiple implementations of a particular data
 * structure. By convention, Libauth identifies chain-specific implementations
 * with a currency symbol suffix.
 *
 * For example, a "transaction" may include different properties depending on
 * the chain for which it is created. The type `TransactionBCH` specifies a
 * transaction intended for the BCH network, while the type `TransactionBTC`
 * specifies a transaction intended for BTC.
 *
 * For convenience, unless another chain is specified, Libauth types refer to
 * their BCH implementation, e.g. `Transaction` is an alias for
 * `TransactionBCH`. This file specifies these default mappings.
 */

export type { AuthenticationProgramStateBCH as AuthenticationProgramState } from '../index.js';
export {
  encodeTransactionCommon as encodeTransaction,
  decodeTransactionCommon as decodeTransaction,
  decodeTransactionUnsafeCommon as decodeTransactionUnsafe,
  OpcodesBCH as Opcodes,
  OpcodeDescriptionsBCH as OpcodeDescriptions,
} from '../index.js';
