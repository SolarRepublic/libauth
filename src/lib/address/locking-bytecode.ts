import { sha256 as internalSha256 } from '../crypto/default-crypto-instances.js';
import type { Sha256 } from '../lib';
import {
  isPayToPublicKeyCompressed,
  isPayToPublicKeyHash,
  isPayToPublicKeyUncompressed,
  isPayToScriptHash20,
} from '../lib.js';

import type { Base58AddressNetwork, CashAddressNetworkPrefix } from './address';
import {
  Base58AddressFormatVersion,
  CashAddressType,
  decodeBase58Address,
  decodeCashAddress,
  encodeBase58AddressFormat,
  encodeCashAddress,
} from './address.js';

/**
 * The most common address types used on bitcoin and bitcoin-like networks. Each
 * address type represents a commonly used locking bytecode pattern.
 *
 * @remarks
 * Addresses are strings that encode information about the network and
 * `lockingBytecode` to which a transaction output can pay.
 *
 * Several address formats exist – `Base58Address` was the format used by the
 * original satoshi client, and is still in use on several active chains (see
 * {@link encodeBase58Address}). On Bitcoin Cash, the `CashAddress` standard is
 * most common (See {@link encodeCashAddress}).
 */
export enum AddressType {
  /**
   * Pay to Public Key (P2PK). This address type is uncommon, and primarily
   * occurs in early blocks because the original satoshi implementation mined
   * rewards to P2PK addresses.
   *
   * There are no standardized address formats for representing a P2PK address.
   * Instead, most applications use the `AddressType.p2pkh` format.
   */
  p2pk = 'P2PK',
  /**
   * Pay to Public Key Hash (P2PKH). The most common address type. P2PKH
   * addresses lock funds using a single private key.
   */
  p2pkh = 'P2PKH',
  /**
   * 20-byte Pay to Script Hash (P2SH20). An address type that locks funds to
   * the 20-byte hash of a script provided in the spending transaction. See
   * BIPs 13 and 16 for details.
   */
  p2sh20 = 'P2SH20',
  /**
   * This `AddressType` represents an address using an unknown or uncommon
   * locking bytecode pattern for which no standardized address formats exist.
   */
  unknown = 'unknown',
}

/**
 * An object representing the contents of an address. This can be used to encode
 * an address or its locking bytecode.
 *
 * See `lockingBytecodeToAddressContents` for details.
 */
export interface AddressContents {
  type: AddressType;
  payload: Uint8Array;
}

const enum Opcodes {
  OP_PUSHBYTES_20 = 0x14,
  OP_PUSHBYTES_33 = 0x21,
  OP_PUSHBYTES_65 = 0x41,
  OP_16 = 0x60,
  OP_RETURN = 0x6a,
  OP_DUP = 0x76,
  OP_EQUAL = 0x87,
  OP_EQUALVERIFY = 0x88,
  OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9,
  OP_CHECKSIG = 0xac,
}

const enum AddressPayload {
  p2pkhStart = 3,
  p2pkhEnd = 23,
  p2sh20Start = 2,
  p2sh20End = 22,
  p2pkUncompressedStart = 1,
  p2pkUncompressedEnd = 66,
  p2pkCompressedStart = 1,
  p2pkCompressedEnd = 34,
}

/**
 * Attempt to match a lockingBytecode to a standard address type for use in
 * address encoding. (See {@link AddressType} for details.)
 *
 * For a locking bytecode matching the Pay to Public Key Hash (P2PKH) pattern,
 * the returned `type` is {@link AddressType.p2pkh} and `payload` is the
 * `HASH160` of the public key.
 *
 * For a locking bytecode matching the 20-byte Pay to Script Hash (P2SH20)
 * pattern, the returned `type` is {@link AddressType.p2sh20} and `payload` is
 * the `HASH160` of the redeeming bytecode, A.K.A. "redeem script hash".
 *
 * For a locking bytecode matching the Pay to Public Key (P2PK) pattern, the
 * returned `type` is {@link AddressType.p2pk} and `payload` is the full
 * public key.
 *
 * Any other locking bytecode will return a `type` of
 * {@link AddressType.unknown} and a payload of the unmodified `bytecode`.
 *
 * @param bytecode - the locking bytecode to match
 */

export const lockingBytecodeToAddressContents = (
  bytecode: Uint8Array
): AddressContents => {
  if (isPayToPublicKeyHash(bytecode)) {
    return {
      payload: bytecode.slice(
        AddressPayload.p2pkhStart,
        AddressPayload.p2pkhEnd
      ),
      type: AddressType.p2pkh,
    };
  }

  if (isPayToScriptHash20(bytecode)) {
    return {
      payload: bytecode.slice(
        AddressPayload.p2sh20Start,
        AddressPayload.p2sh20End
      ),
      type: AddressType.p2sh20,
    };
  }

  if (isPayToPublicKeyUncompressed(bytecode)) {
    return {
      payload: bytecode.slice(
        AddressPayload.p2pkUncompressedStart,
        AddressPayload.p2pkUncompressedEnd
      ),
      type: AddressType.p2pk,
    };
  }

  if (isPayToPublicKeyCompressed(bytecode)) {
    return {
      payload: bytecode.slice(
        AddressPayload.p2pkCompressedStart,
        AddressPayload.p2pkCompressedEnd
      ),
      type: AddressType.p2pk,
    };
  }

  return { payload: bytecode.slice(), type: AddressType.unknown };
};

/**
 * Get the locking bytecode for a valid {@link AddressContents}. See
 * {@link lockingBytecodeToAddressContents} for details.
 *
 * For {@link AddressContents} of `type` {@link AddressType.unknown}, this
 * method returns the `payload` without modification.
 *
 * @param addressContents - the `AddressContents` to encode
 */
export const addressContentsToLockingBytecode = (
  addressContents: AddressContents
) => {
  if (addressContents.type === AddressType.p2pkh) {
    return Uint8Array.from([
      Opcodes.OP_DUP,
      Opcodes.OP_HASH160,
      Opcodes.OP_PUSHBYTES_20,
      ...addressContents.payload,
      Opcodes.OP_EQUALVERIFY,
      Opcodes.OP_CHECKSIG,
    ]);
  }
  if (addressContents.type === AddressType.p2sh20) {
    return Uint8Array.from([
      Opcodes.OP_HASH160,
      Opcodes.OP_PUSHBYTES_20,
      ...addressContents.payload,
      Opcodes.OP_EQUAL,
    ]);
  }
  if (addressContents.type === AddressType.p2pk) {
    const compressedPublicKeyLength = 33;
    return addressContents.payload.length === compressedPublicKeyLength
      ? Uint8Array.from([
          Opcodes.OP_PUSHBYTES_33,
          ...addressContents.payload,
          Opcodes.OP_CHECKSIG,
        ])
      : Uint8Array.from([
          Opcodes.OP_PUSHBYTES_65,
          ...addressContents.payload,
          Opcodes.OP_CHECKSIG,
        ]);
  }
  return addressContents.payload;
};

/**
 * Encode a locking bytecode as a CashAddress given a network prefix.
 *
 * If `bytecode` matches a standard pattern, it is encoded using the proper
 * address type and returned as a valid CashAddress (string).
 *
 * If `bytecode` cannot be encoded as an address (i.e. because the pattern is
 * not standard), the resulting {@link AddressContents} is returned.
 *
 * @param bytecode - the locking bytecode to encode
 * @param prefix - the network prefix to use, e.g. `bitcoincash`, `bchtest`, or
 * `bchreg`
 */
export const lockingBytecodeToCashAddress = <
  Prefix extends string = CashAddressNetworkPrefix
>(
  bytecode: Uint8Array,
  prefix: Prefix
) => {
  const contents = lockingBytecodeToAddressContents(bytecode);
  if (contents.type === AddressType.p2pkh) {
    return encodeCashAddress(prefix, CashAddressType.p2pkh, contents.payload);
  }
  if (contents.type === AddressType.p2sh20) {
    return encodeCashAddress(prefix, CashAddressType.p2sh20, contents.payload);
  }

  return contents;
};

export enum LockingBytecodeEncodingError {
  unknownCashAddressType = 'This CashAddress uses an unknown address type.',
}

/**
 * Convert a CashAddress to its respective locking bytecode.
 *
 * This method returns the locking bytecode and network prefix. If an error
 * occurs, an error message is returned as a string.
 *
 * @param address - the CashAddress to convert
 */
export const cashAddressToLockingBytecode = (address: string) => {
  const decoded = decodeCashAddress(address);
  if (typeof decoded === 'string') return decoded;

  if (decoded.type === CashAddressType.p2pkh) {
    return {
      bytecode: addressContentsToLockingBytecode({
        payload: decoded.hash,
        type: AddressType.p2pkh,
      }),
      prefix: decoded.prefix,
    };
  }

  if (decoded.type === CashAddressType.p2sh20) {
    return {
      bytecode: addressContentsToLockingBytecode({
        payload: decoded.hash,
        type: AddressType.p2sh20,
      }),
      prefix: decoded.prefix,
    };
  }

  return LockingBytecodeEncodingError.unknownCashAddressType;
};

/**
 * Encode a locking bytecode as a Base58Address for a given network.
 *
 * If `bytecode` matches a standard pattern, it is encoded using the proper
 * address type and returned as a valid Base58Address (string).
 *
 * If `bytecode` cannot be encoded as an address (i.e. because the pattern is
 * not standard), the resulting {@link AddressContents} is returned.
 *
 * @param bytecode - the locking bytecode to encode
 * @param network - the network for which to encode the address (`mainnet` or
 * `testnet`)
 * @param sha256 - an implementation of sha256 (defaults to the internal WASM
 * implementation)
 */
export const lockingBytecodeToBase58Address = (
  bytecode: Uint8Array,
  network: Base58AddressNetwork,
  sha256: { hash: Sha256['hash'] } = internalSha256
) => {
  const contents = lockingBytecodeToAddressContents(bytecode);

  if (contents.type === AddressType.p2pkh) {
    return encodeBase58AddressFormat(
      {
        copayBCH: Base58AddressFormatVersion.p2pkhCopayBCH,
        mainnet: Base58AddressFormatVersion.p2pkh,
        testnet: Base58AddressFormatVersion.p2pkhTestnet,
      }[network],
      contents.payload,
      sha256
    );
  }
  if (contents.type === AddressType.p2sh20) {
    return encodeBase58AddressFormat(
      {
        copayBCH: Base58AddressFormatVersion.p2sh20CopayBCH,
        mainnet: Base58AddressFormatVersion.p2sh20,
        testnet: Base58AddressFormatVersion.p2sh20Testnet,
      }[network],
      contents.payload,
      sha256
    );
  }

  return contents;
};

/**
 * Convert a Base58Address to its respective locking bytecode.
 *
 * This method returns the locking bytecode and network version. If an error
 * occurs, an error message is returned as a string.
 *
 * @param address - the CashAddress to convert
 */
export const base58AddressToLockingBytecode = (
  address: string,
  sha256: { hash: Sha256['hash'] } = internalSha256
) => {
  const decoded = decodeBase58Address(address, sha256);
  if (typeof decoded === 'string') return decoded;

  return {
    bytecode: addressContentsToLockingBytecode({
      payload: decoded.payload,
      type: [
        Base58AddressFormatVersion.p2pkh,
        Base58AddressFormatVersion.p2pkhCopayBCH,
        Base58AddressFormatVersion.p2pkhTestnet,
      ].includes(decoded.version)
        ? AddressType.p2pkh
        : AddressType.p2sh20,
    }),
    version: decoded.version,
  };
};
