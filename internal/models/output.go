// Package models defines JSON output schema for Chain Lens transaction analysis.
package models

// Vout represents a transaction output in the JSON output.
type Vout struct {
	// Output index (0-based)
	N uint32 `json:"n"`

	// Value in satoshis
	ValueSats uint64 `json:"value_sats"`

	// Script fields
	ScriptPubkeyHex string `json:"script_pubkey_hex"`
	ScriptAsm       string `json:"script_asm"`

	// Output classification
	ScriptType string  `json:"script_type"` // p2pkh, p2sh, p2wpkh, p2wsh, p2tr, op_return, unknown
	Address    *string `json:"address"`     // nil for op_return and unknown

	// OP_RETURN specific fields (only present for op_return outputs)
	OPReturnDataHex  *string `json:"op_return_data_hex,omitempty"`
	OPReturnDataUTF8 *string `json:"op_return_data_utf8,omitempty"`
	OPReturnProtocol *string `json:"op_return_protocol,omitempty"`
}

// OutputScriptType constants for output classification.
const (
	OutputScriptTypeP2PKH    = "p2pkh"
	OutputScriptTypeP2SH     = "p2sh"
	OutputScriptTypeP2WPKH   = "p2wpkh"
	OutputScriptTypeP2WSH    = "p2wsh"
	OutputScriptTypeP2TR     = "p2tr"
	OutputScriptTypeOPReturn = "op_return"
	OutputScriptTypeUnknown  = "unknown"
)

// OP_RETURN protocol identifiers.
const (
	OPReturnProtocolOmni           = "omni"
	OPReturnProtocolOpenTimestamps = "opentimestamps"
	OPReturnProtocolUnknown        = "unknown"
)

// OP_RETURN protocol prefixes (hex).
var (
	// "omni" in ASCII = 0x6f6d6e69
	OmniPrefix = []byte{0x6f, 0x6d, 0x6e, 0x69}
	// OpenTimestamps prefix
	OpenTimestampsPrefix = []byte{0x01, 0x09, 0xf9, 0x11, 0x02}
)

// Script template lengths for classification.
const (
	// P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	P2PKHScriptLen = 25

	// P2SH: OP_HASH160 <20 bytes> OP_EQUAL
	P2SHScriptLen = 23

	// P2WPKH: OP_0 <20 bytes>
	P2WPKHScriptLen = 22

	// P2WSH: OP_0 <32 bytes>
	P2WSHScriptLen = 34

	// P2TR: OP_1 <32 bytes>
	P2TRScriptLen = 34
)
