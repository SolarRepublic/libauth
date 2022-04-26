/**
 * The `BCH_2022_05` instruction set.
 */

export enum OpcodesBCH2022 {
  /**
   * A.K.A. `OP_FALSE` or `OP_PUSHBYTES_0`
   */
  OP_0 = 0x00,
  OP_PUSHBYTES_1 = 0x01,
  OP_PUSHBYTES_2 = 0x02,
  OP_PUSHBYTES_3 = 0x03,
  OP_PUSHBYTES_4 = 0x04,
  OP_PUSHBYTES_5 = 0x05,
  OP_PUSHBYTES_6 = 0x06,
  OP_PUSHBYTES_7 = 0x07,
  OP_PUSHBYTES_8 = 0x08,
  OP_PUSHBYTES_9 = 0x09,
  OP_PUSHBYTES_10 = 0x0a,
  OP_PUSHBYTES_11 = 0x0b,
  OP_PUSHBYTES_12 = 0x0c,
  OP_PUSHBYTES_13 = 0x0d,
  OP_PUSHBYTES_14 = 0x0e,
  OP_PUSHBYTES_15 = 0x0f,
  OP_PUSHBYTES_16 = 0x10,
  OP_PUSHBYTES_17 = 0x11,
  OP_PUSHBYTES_18 = 0x12,
  OP_PUSHBYTES_19 = 0x13,
  OP_PUSHBYTES_20 = 0x14,
  OP_PUSHBYTES_21 = 0x15,
  OP_PUSHBYTES_22 = 0x16,
  OP_PUSHBYTES_23 = 0x17,
  OP_PUSHBYTES_24 = 0x18,
  OP_PUSHBYTES_25 = 0x19,
  OP_PUSHBYTES_26 = 0x1a,
  OP_PUSHBYTES_27 = 0x1b,
  OP_PUSHBYTES_28 = 0x1c,
  OP_PUSHBYTES_29 = 0x1d,
  OP_PUSHBYTES_30 = 0x1e,
  OP_PUSHBYTES_31 = 0x1f,
  OP_PUSHBYTES_32 = 0x20,
  OP_PUSHBYTES_33 = 0x21,
  OP_PUSHBYTES_34 = 0x22,
  OP_PUSHBYTES_35 = 0x23,
  OP_PUSHBYTES_36 = 0x24,
  OP_PUSHBYTES_37 = 0x25,
  OP_PUSHBYTES_38 = 0x26,
  OP_PUSHBYTES_39 = 0x27,
  OP_PUSHBYTES_40 = 0x28,
  OP_PUSHBYTES_41 = 0x29,
  OP_PUSHBYTES_42 = 0x2a,
  OP_PUSHBYTES_43 = 0x2b,
  OP_PUSHBYTES_44 = 0x2c,
  OP_PUSHBYTES_45 = 0x2d,
  OP_PUSHBYTES_46 = 0x2e,
  OP_PUSHBYTES_47 = 0x2f,
  OP_PUSHBYTES_48 = 0x30,
  OP_PUSHBYTES_49 = 0x31,
  OP_PUSHBYTES_50 = 0x32,
  OP_PUSHBYTES_51 = 0x33,
  OP_PUSHBYTES_52 = 0x34,
  OP_PUSHBYTES_53 = 0x35,
  OP_PUSHBYTES_54 = 0x36,
  OP_PUSHBYTES_55 = 0x37,
  OP_PUSHBYTES_56 = 0x38,
  OP_PUSHBYTES_57 = 0x39,
  OP_PUSHBYTES_58 = 0x3a,
  OP_PUSHBYTES_59 = 0x3b,
  OP_PUSHBYTES_60 = 0x3c,
  OP_PUSHBYTES_61 = 0x3d,
  OP_PUSHBYTES_62 = 0x3e,
  OP_PUSHBYTES_63 = 0x3f,
  OP_PUSHBYTES_64 = 0x40,
  OP_PUSHBYTES_65 = 0x41,
  OP_PUSHBYTES_66 = 0x42,
  OP_PUSHBYTES_67 = 0x43,
  OP_PUSHBYTES_68 = 0x44,
  OP_PUSHBYTES_69 = 0x45,
  OP_PUSHBYTES_70 = 0x46,
  OP_PUSHBYTES_71 = 0x47,
  OP_PUSHBYTES_72 = 0x48,
  OP_PUSHBYTES_73 = 0x49,
  OP_PUSHBYTES_74 = 0x4a,
  OP_PUSHBYTES_75 = 0x4b,
  OP_PUSHDATA_1 = 0x4c,
  OP_PUSHDATA_2 = 0x4d,
  OP_PUSHDATA_4 = 0x4e,
  OP_1NEGATE = 0x4f,
  OP_RESERVED = 0x50,
  /**
   * A.K.A. `OP_TRUE`
   */
  OP_1 = 0x51,
  OP_2 = 0x52,
  OP_3 = 0x53,
  OP_4 = 0x54,
  OP_5 = 0x55,
  OP_6 = 0x56,
  OP_7 = 0x57,
  OP_8 = 0x58,
  OP_9 = 0x59,
  OP_10 = 0x5a,
  OP_11 = 0x5b,
  OP_12 = 0x5c,
  OP_13 = 0x5d,
  OP_14 = 0x5e,
  OP_15 = 0x5f,
  OP_16 = 0x60,
  OP_NOP = 0x61,
  OP_VER = 0x62,
  OP_IF = 0x63,
  OP_NOTIF = 0x64,
  OP_VERIF = 0x65,
  OP_VERNOTIF = 0x66,
  OP_ELSE = 0x67,
  OP_ENDIF = 0x68,
  OP_VERIFY = 0x69,
  OP_RETURN = 0x6a,
  OP_TOALTSTACK = 0x6b,
  OP_FROMALTSTACK = 0x6c,
  OP_2DROP = 0x6d,
  OP_2DUP = 0x6e,
  OP_3DUP = 0x6f,
  OP_2OVER = 0x70,
  OP_2ROT = 0x71,
  OP_2SWAP = 0x72,
  OP_IFDUP = 0x73,
  OP_DEPTH = 0x74,
  OP_DROP = 0x75,
  OP_DUP = 0x76,
  OP_NIP = 0x77,
  OP_OVER = 0x78,
  OP_PICK = 0x79,
  OP_ROLL = 0x7a,
  OP_ROT = 0x7b,
  OP_SWAP = 0x7c,
  OP_TUCK = 0x7d,
  OP_CAT = 0x7e,
  OP_SPLIT = 0x7f,
  OP_NUM2BIN = 0x80,
  OP_BIN2NUM = 0x81,
  OP_SIZE = 0x82,
  OP_INVERT = 0x83,
  OP_AND = 0x84,
  OP_OR = 0x85,
  OP_XOR = 0x86,
  OP_EQUAL = 0x87,
  OP_EQUALVERIFY = 0x88,
  OP_RESERVED1 = 0x89,
  OP_RESERVED2 = 0x8a,
  OP_1ADD = 0x8b,
  OP_1SUB = 0x8c,
  OP_2MUL = 0x8d,
  OP_2DIV = 0x8e,
  OP_NEGATE = 0x8f,
  OP_ABS = 0x90,
  OP_NOT = 0x91,
  OP_0NOTEQUAL = 0x92,
  OP_ADD = 0x93,
  OP_SUB = 0x94,
  OP_MUL = 0x95,
  OP_DIV = 0x96,
  OP_MOD = 0x97,
  OP_LSHIFT = 0x98,
  OP_RSHIFT = 0x99,
  OP_BOOLAND = 0x9a,
  OP_BOOLOR = 0x9b,
  OP_NUMEQUAL = 0x9c,
  OP_NUMEQUALVERIFY = 0x9d,
  OP_NUMNOTEQUAL = 0x9e,
  OP_LESSTHAN = 0x9f,
  OP_GREATERTHAN = 0xa0,
  OP_LESSTHANOREQUAL = 0xa1,
  OP_GREATERTHANOREQUAL = 0xa2,
  OP_MIN = 0xa3,
  OP_MAX = 0xa4,
  OP_WITHIN = 0xa5,
  OP_RIPEMD160 = 0xa6,
  OP_SHA1 = 0xa7,
  OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9,
  OP_HASH256 = 0xaa,
  OP_CODESEPARATOR = 0xab,
  OP_CHECKSIG = 0xac,
  OP_CHECKSIGVERIFY = 0xad,
  OP_CHECKMULTISIG = 0xae,
  OP_CHECKMULTISIGVERIFY = 0xaf,
  OP_NOP1 = 0xb0,
  OP_CHECKLOCKTIMEVERIFY = 0xb1,
  OP_CHECKSEQUENCEVERIFY = 0xb2,
  OP_NOP4 = 0xb3,
  OP_NOP5 = 0xb4,
  OP_NOP6 = 0xb5,
  OP_NOP7 = 0xb6,
  OP_NOP8 = 0xb7,
  OP_NOP9 = 0xb8,
  OP_NOP10 = 0xb9,
  OP_CHECKDATASIG = 0xba,
  OP_CHECKDATASIGVERIFY = 0xbb,
  OP_REVERSEBYTES = 0xbc,
  /**
   * First codepoint left undefined before nullary introspection operations.
   */
  OP_UNKNOWN189 = 0xbd,
  OP_UNKNOWN190 = 0xbe,
  /**
   * Last codepoint left undefined before nullary introspection operations.
   */
  OP_UNKNOWN191 = 0xbf,
  OP_INPUTINDEX = 0xc0,
  OP_ACTIVEBYTECODE = 0xc1,
  OP_TXVERSION = 0xc2,
  OP_TXINPUTCOUNT = 0xc3,
  OP_TXOUTPUTCOUNT = 0xc4,
  OP_TXLOCKTIME = 0xc5,
  OP_UTXOVALUE = 0xc6,
  OP_UTXOBYTECODE = 0xc7,
  OP_OUTPOINTTXHASH = 0xc8,
  OP_OUTPOINTINDEX = 0xc9,
  OP_INPUTBYTECODE = 0xca,
  OP_INPUTSEQUENCENUMBER = 0xcb,
  OP_OUTPUTVALUE = 0xcc,
  OP_OUTPUTBYTECODE = 0xcd,
  /**
   * Reserved for unary introspection operations.
   */
  OP_RESERVED3 = 0xce,
  /**
   * Reserved for unary introspection operations.
   */
  OP_RESERVED4 = 0xcf,
  OP_UNKNOWN208 = 0xd0,
  OP_UNKNOWN209 = 0xd1,
  OP_UNKNOWN210 = 0xd2,
  OP_UNKNOWN211 = 0xd3,
  OP_UNKNOWN212 = 0xd4,
  OP_UNKNOWN213 = 0xd5,
  OP_UNKNOWN214 = 0xd6,
  OP_UNKNOWN215 = 0xd7,
  OP_UNKNOWN216 = 0xd8,
  OP_UNKNOWN217 = 0xd9,
  OP_UNKNOWN218 = 0xda,
  OP_UNKNOWN219 = 0xdb,
  OP_UNKNOWN220 = 0xdc,
  OP_UNKNOWN221 = 0xdd,
  OP_UNKNOWN222 = 0xde,
  OP_UNKNOWN223 = 0xdf,
  OP_UNKNOWN224 = 0xe0,
  OP_UNKNOWN225 = 0xe1,
  OP_UNKNOWN226 = 0xe2,
  OP_UNKNOWN227 = 0xe3,
  OP_UNKNOWN228 = 0xe4,
  OP_UNKNOWN229 = 0xe5,
  OP_UNKNOWN230 = 0xe6,
  OP_UNKNOWN231 = 0xe7,
  OP_UNKNOWN232 = 0xe8,
  OP_UNKNOWN233 = 0xe9,
  OP_UNKNOWN234 = 0xea,
  OP_UNKNOWN235 = 0xeb,
  OP_UNKNOWN236 = 0xec,
  OP_UNKNOWN237 = 0xed,
  OP_UNKNOWN238 = 0xee,
  OP_UNKNOWN239 = 0xef,
  /**
   * A.K.A. `OP_PREFIX_BEGIN`
   */
  OP_UNKNOWN240 = 0xf0,
  OP_UNKNOWN241 = 0xf1,
  OP_UNKNOWN242 = 0xf2,
  OP_UNKNOWN243 = 0xf3,
  OP_UNKNOWN244 = 0xf4,
  OP_UNKNOWN245 = 0xf5,
  OP_UNKNOWN246 = 0xf6,
  /**
   * A.K.A. `OP_PREFIX_END`
   */
  OP_UNKNOWN247 = 0xf7,
  OP_UNKNOWN248 = 0xf8,
  OP_UNKNOWN249 = 0xf9,
  OP_UNKNOWN250 = 0xfa,
  OP_UNKNOWN251 = 0xfb,
  OP_UNKNOWN252 = 0xfc,
  OP_UNKNOWN253 = 0xfd,
  OP_UNKNOWN254 = 0xfe,
  OP_UNKNOWN255 = 0xff,
}

export enum OpcodeAlternateNamesBCH {
  /**
   * A.K.A. `OP_0`
   */
  OP_FALSE = 0x00,
  /**
   * A.K.A. `OP_0`
   */
  OP_PUSHBYTES_0 = 0x00,
  /**
   * A.K.A. `OP_1`
   */
  OP_TRUE = 0x51,
  /**
   * A.K.A. `OP_CHECKLOCKTIMEVERIFY`
   */
  OP_NOP2 = 0xb1,
  /**
   * A.K.A. `OP_CHECKSEQUENCEVERIFY`
   */
  OP_NOP3 = 0xb2,
  /**
   * A.K.A. `OP_UNKNOWN240`. Some implementations have reserved opcodes
   * `0xf0` through `0xf7` for a future range of multi-byte opcodes, though none
   * are yet available on the network.
   */
  OP_PREFIX_BEGIN = 0xf0,
  /**
   * A.K.A. `OP_UNKNOWN247`. Some implementations have reserved opcodes
   * `0xf0` through `0xf7` for a future range of multi-byte opcodes, though none
   * are yet available on the network.
   */
  OP_PREFIX_END = 0xf7,
  /**
   * `OP_SMALLINTEGER` is used internally for template matching in the C++
   * implementation. When found on the network, it is `OP_UNKNOWN250`.
   */
  OP_SMALLINTEGER = 0xfa,
  /**
   * `OP_PUBKEYS` is used internally for template matching in the C++
   * implementation. When found on the network, it is `OP_UNKNOWN251`.
   */
  OP_PUBKEYS = 0xfb,
  /**
   * `OP_PUBKEYHASH` is used internally for template matching in the C++
   * implementation. When found on the network, it is `OP_UNKNOWN253`.
   */
  OP_PUBKEYHASH = 0xfd,
  /**
   * `OP_PUBKEY` is used internally for template matching in the C++
   * implementation. When found on the network, it is `OP_UNKNOWN254`.
   */
  OP_PUBKEY = 0xfe,
  /**
   * `OP_INVALIDOPCODE` is described as such for testing in the C++
   * implementation. When found on the network, it is `OP_UNKNOWN255`.
   */
  OP_INVALIDOPCODE = 0xff,
}
