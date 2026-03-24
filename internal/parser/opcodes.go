// Package parser provides Bitcoin opcode definitions and script disassembly.
package parser

import "fmt"

// Opcode represents a Bitcoin script opcode.
type Opcode byte

// Bitcoin opcodes (complete list from Bitcoin Core)
const (
	// Push value
	OP_0         Opcode = 0x00
	OP_FALSE     Opcode = 0x00
	OP_PUSHDATA1 Opcode = 0x4c
	OP_PUSHDATA2 Opcode = 0x4d
	OP_PUSHDATA4 Opcode = 0x4e
	OP_1NEGATE   Opcode = 0x4f
	OP_RESERVED  Opcode = 0x50
	OP_1         Opcode = 0x51
	OP_TRUE      Opcode = 0x51
	OP_2         Opcode = 0x52
	OP_3         Opcode = 0x53
	OP_4         Opcode = 0x54
	OP_5         Opcode = 0x55
	OP_6         Opcode = 0x56
	OP_7         Opcode = 0x57
	OP_8         Opcode = 0x58
	OP_9         Opcode = 0x59
	OP_10        Opcode = 0x5a
	OP_11        Opcode = 0x5b
	OP_12        Opcode = 0x5c
	OP_13        Opcode = 0x5d
	OP_14        Opcode = 0x5e
	OP_15        Opcode = 0x5f
	OP_16        Opcode = 0x60

	// Flow control
	OP_NOP      Opcode = 0x61
	OP_VER      Opcode = 0x62
	OP_IF       Opcode = 0x63
	OP_NOTIF    Opcode = 0x64
	OP_VERIF    Opcode = 0x65
	OP_VERNOTIF Opcode = 0x66
	OP_ELSE     Opcode = 0x67
	OP_ENDIF    Opcode = 0x68
	OP_VERIFY   Opcode = 0x69
	OP_RETURN   Opcode = 0x6a

	// Stack operations
	OP_TOALTSTACK   Opcode = 0x6b
	OP_FROMALTSTACK Opcode = 0x6c
	OP_2DROP        Opcode = 0x6d
	OP_2DUP         Opcode = 0x6e
	OP_3DUP         Opcode = 0x6f
	OP_2OVER        Opcode = 0x70
	OP_2ROT         Opcode = 0x71
	OP_2SWAP        Opcode = 0x72
	OP_IFDUP        Opcode = 0x73
	OP_DEPTH        Opcode = 0x74
	OP_DROP         Opcode = 0x75
	OP_DUP          Opcode = 0x76
	OP_NIP          Opcode = 0x77
	OP_OVER         Opcode = 0x78
	OP_PICK         Opcode = 0x79
	OP_ROLL         Opcode = 0x7a
	OP_ROT          Opcode = 0x7b
	OP_SWAP         Opcode = 0x7c
	OP_TUCK         Opcode = 0x7d
	
	// Splice operations
	OP_CAT    Opcode = 0x7e // Disabled
	OP_SUBSTR Opcode = 0x7f // Disabled
	OP_LEFT   Opcode = 0x80 // Disabled
	OP_RIGHT  Opcode = 0x81 // Disabled
	OP_SIZE   Opcode = 0x82

	// Bit logic
	OP_INVERT      Opcode = 0x83 // Disabled
	OP_AND         Opcode = 0x84 // Disabled
	OP_OR          Opcode = 0x85 // Disabled
	OP_XOR         Opcode = 0x86 // Disabled
	OP_EQUAL       Opcode = 0x87
	OP_EQUALVERIFY Opcode = 0x88
	OP_RESERVED1   Opcode = 0x89
	OP_RESERVED2   Opcode = 0x8a

	// Numeric
	OP_1ADD      Opcode = 0x8b
	OP_1SUB      Opcode = 0x8c
	OP_2MUL      Opcode = 0x8d // Disabled
	OP_2DIV      Opcode = 0x8e // Disabled
	OP_NEGATE    Opcode = 0x8f
	OP_ABS       Opcode = 0x90
	OP_NOT       Opcode = 0x91
	OP_0NOTEQUAL Opcode = 0x92

	OP_ADD    Opcode = 0x93
	OP_SUB    Opcode = 0x94
	OP_MUL    Opcode = 0x95 // Disabled
	OP_DIV    Opcode = 0x96 // Disabled
	OP_MOD    Opcode = 0x97 // Disabled
	OP_LSHIFT Opcode = 0x98 // Disabled
	OP_RSHIFT Opcode = 0x99 // Disabled

	OP_BOOLAND            Opcode = 0x9a
	OP_BOOLOR             Opcode = 0x9b
	OP_NUMEQUAL           Opcode = 0x9c
	OP_NUMEQUALVERIFY     Opcode = 0x9d
	OP_NUMNOTEQUAL        Opcode = 0x9e
	OP_LESSTHAN           Opcode = 0x9f
	OP_GREATERTHAN        Opcode = 0xa0
	OP_LESSTHANOREQUAL    Opcode = 0xa1
	OP_GREATERTHANOREQUAL Opcode = 0xa2
	OP_MIN                Opcode = 0xa3
	OP_MAX                Opcode = 0xa4

	OP_WITHIN Opcode = 0xa5

	// Crypto
	OP_RIPEMD160           Opcode = 0xa6
	OP_SHA1                Opcode = 0xa7
	OP_SHA256              Opcode = 0xa8
	OP_HASH160             Opcode = 0xa9
	OP_HASH256             Opcode = 0xaa
	OP_CODESEPARATOR       Opcode = 0xab
	OP_CHECKSIG            Opcode = 0xac
	OP_CHECKSIGVERIFY      Opcode = 0xad
	OP_CHECKMULTISIG       Opcode = 0xae
	OP_CHECKMULTISIGVERIFY Opcode = 0xaf

	// Expansion
	OP_NOP1                Opcode = 0xb0
	OP_CHECKLOCKTIMEVERIFY Opcode = 0xb1
	OP_NOP2                Opcode = 0xb1
	OP_CHECKSEQUENCEVERIFY Opcode = 0xb2
	OP_NOP3                Opcode = 0xb2
	OP_NOP4                Opcode = 0xb3
	OP_NOP5                Opcode = 0xb4
	OP_NOP6                Opcode = 0xb5
	OP_NOP7                Opcode = 0xb6
	OP_NOP8                Opcode = 0xb7
	OP_NOP9                Opcode = 0xb8
	OP_NOP10               Opcode = 0xb9

	// Taproot
	OP_CHECKSIGADD Opcode = 0xba

	// Invalid
	OP_INVALIDOPCODE Opcode = 0xff
)

// opcodeNames maps opcodes to their string names.
var opcodeNames = map[Opcode]string{
	OP_0:                   "OP_0",
	OP_PUSHDATA1:           "OP_PUSHDATA1",
	OP_PUSHDATA2:           "OP_PUSHDATA2",
	OP_PUSHDATA4:           "OP_PUSHDATA4",
	OP_1NEGATE:             "OP_1NEGATE",
	OP_RESERVED:            "OP_RESERVED",
	OP_1:                   "OP_1",
	OP_2:                   "OP_2",
	OP_3:                   "OP_3",
	OP_4:                   "OP_4",
	OP_5:                   "OP_5",
	OP_6:                   "OP_6",
	OP_7:                   "OP_7",
	OP_8:                   "OP_8",
	OP_9:                   "OP_9",
	OP_10:                  "OP_10",
	OP_11:                  "OP_11",
	OP_12:                  "OP_12",
	OP_13:                  "OP_13",
	OP_14:                  "OP_14",
	OP_15:                  "OP_15",
	OP_16:                  "OP_16",
	OP_NOP:                 "OP_NOP",
	OP_VER:                 "OP_VER",
	OP_IF:                  "OP_IF",
	OP_NOTIF:               "OP_NOTIF",
	OP_VERIF:               "OP_VERIF",
	OP_VERNOTIF:            "OP_VERNOTIF",
	OP_ELSE:                "OP_ELSE",
	OP_ENDIF:               "OP_ENDIF",
	OP_VERIFY:              "OP_VERIFY",
	OP_RETURN:              "OP_RETURN",
	OP_TOALTSTACK:          "OP_TOALTSTACK",
	OP_FROMALTSTACK:        "OP_FROMALTSTACK",
	OP_2DROP:               "OP_2DROP",
	OP_2DUP:                "OP_2DUP",
	OP_3DUP:                "OP_3DUP",
	OP_2OVER:               "OP_2OVER",
	OP_2ROT:                "OP_2ROT",
	OP_2SWAP:               "OP_2SWAP",
	OP_IFDUP:               "OP_IFDUP",
	OP_DEPTH:               "OP_DEPTH",
	OP_DROP:                "OP_DROP",
	OP_DUP:                 "OP_DUP",
	OP_NIP:                 "OP_NIP",
	OP_OVER:                "OP_OVER",
	OP_PICK:                "OP_PICK",
	OP_ROLL:                "OP_ROLL",
	OP_ROT:                 "OP_ROT",
	OP_SWAP:                "OP_SWAP",
	OP_TUCK:                "OP_TUCK",
	OP_CAT:                 "OP_CAT",
	OP_SUBSTR:              "OP_SUBSTR",
	OP_LEFT:                "OP_LEFT",
	OP_RIGHT:               "OP_RIGHT",
	OP_SIZE:                "OP_SIZE",
	OP_INVERT:              "OP_INVERT",
	OP_AND:                 "OP_AND",
	OP_OR:                  "OP_OR",
	OP_XOR:                 "OP_XOR",
	OP_EQUAL:               "OP_EQUAL",
	OP_EQUALVERIFY:         "OP_EQUALVERIFY",
	OP_RESERVED1:           "OP_RESERVED1",
	OP_RESERVED2:           "OP_RESERVED2",
	OP_1ADD:                "OP_1ADD",
	OP_1SUB:                "OP_1SUB",
	OP_2MUL:                "OP_2MUL",
	OP_2DIV:                "OP_2DIV",
	OP_NEGATE:              "OP_NEGATE",
	OP_ABS:                 "OP_ABS",
	OP_NOT:                 "OP_NOT",
	OP_0NOTEQUAL:           "OP_0NOTEQUAL",
	OP_ADD:                 "OP_ADD",
	OP_SUB:                 "OP_SUB",
	OP_MUL:                 "OP_MUL",
	OP_DIV:                 "OP_DIV",
	OP_MOD:                 "OP_MOD",
	OP_LSHIFT:              "OP_LSHIFT",
	OP_RSHIFT:              "OP_RSHIFT",
	OP_BOOLAND:             "OP_BOOLAND",
	OP_BOOLOR:              "OP_BOOLOR",
	OP_NUMEQUAL:            "OP_NUMEQUAL",
	OP_NUMEQUALVERIFY:      "OP_NUMEQUALVERIFY",
	OP_NUMNOTEQUAL:         "OP_NUMNOTEQUAL",
	OP_LESSTHAN:            "OP_LESSTHAN",
	OP_GREATERTHAN:         "OP_GREATERTHAN",
	OP_LESSTHANOREQUAL:     "OP_LESSTHANOREQUAL",
	OP_GREATERTHANOREQUAL:  "OP_GREATERTHANOREQUAL",
	OP_MIN:                 "OP_MIN",
	OP_MAX:                 "OP_MAX",
	OP_WITHIN:              "OP_WITHIN",
	OP_RIPEMD160:           "OP_RIPEMD160",
	OP_SHA1:                "OP_SHA1",
	OP_SHA256:              "OP_SHA256",
	OP_HASH160:             "OP_HASH160",
	OP_HASH256:             "OP_HASH256",
	OP_CODESEPARATOR:       "OP_CODESEPARATOR",
	OP_CHECKSIG:            "OP_CHECKSIG",
	OP_CHECKSIGVERIFY:      "OP_CHECKSIGVERIFY",
	OP_CHECKMULTISIG:       "OP_CHECKMULTISIG",
	OP_CHECKMULTISIGVERIFY: "OP_CHECKMULTISIGVERIFY",
	OP_NOP1:                "OP_NOP1",
	OP_CHECKLOCKTIMEVERIFY: "OP_CHECKLOCKTIMEVERIFY",
	OP_CHECKSEQUENCEVERIFY: "OP_CHECKSEQUENCEVERIFY",
	OP_NOP4:                "OP_NOP4",
	OP_NOP5:                "OP_NOP5",
	OP_NOP6:                "OP_NOP6",
	OP_NOP7:                "OP_NOP7",
	OP_NOP8:                "OP_NOP8",
	OP_NOP9:                "OP_NOP9",
	OP_NOP10:               "OP_NOP10",
	OP_CHECKSIGADD:         "OP_CHECKSIGADD",
	OP_INVALIDOPCODE:       "OP_INVALIDOPCODE",
}

// OpcodeName returns the string name of an opcode.
func OpcodeName(op Opcode) string {
	if name, ok := opcodeNames[op]; ok {
		return name
	}
	return fmt.Sprintf("OP_UNKNOWN_0x%02x", byte(op))
}

// IsPushOpcode returns true if the opcode is a direct push (0x01-0x4b).
func IsPushOpcode(op byte) bool {
	return op >= 0x01 && op <= 0x4b
}

// IsSmallInteger returns true if the opcode represents a small integer (OP_0 or OP_1-OP_16).
func IsSmallInteger(op Opcode) bool {
	return op == OP_0 || (op >= OP_1 && op <= OP_16)
}

// SmallIntegerValue returns the integer value for a small integer opcode.
func SmallIntegerValue(op Opcode) int {
	if op == OP_0 {
		return 0
	}
	if op >= OP_1 && op <= OP_16 {
		return int(op) - int(OP_1) + 1
	}
	return -1 // Not a small integer opcode
}
