// Package models defines JSON output schema for Chain Lens transaction analysis.
package models

// Vin represents a transaction input in the JSON output.
type Vin struct {
	// Outpoint reference (which UTXO is being spent)
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`

	// Sequence number (used for RBF and relative timelocks)
	Sequence uint32 `json:"sequence"`

	// ScriptSig (unlocking script)
	ScriptSigHex string `json:"script_sig_hex"`
	ScriptAsm    string `json:"script_asm"`

	// Witness data (empty array for legacy, witness stack for SegWit)
	Witness []string `json:"witness"`

	// For p2wsh and p2sh-p2wsh: disassembly of the witnessScript
	WitnessScriptAsm *string `json:"witness_script_asm,omitempty"`

	// Input classification
	ScriptType string  `json:"script_type"` // p2pkh, p2sh-p2wpkh, p2sh-p2wsh, p2wpkh, p2wsh, p2tr_keypath, p2tr_scriptpath, unknown
	Address    *string `json:"address"`     // nil for unrecognized types

	// Prevout information (the output being spent)
	Prevout VinPrevout `json:"prevout"`

	// Relative timelock (BIP68)
	RelativeTimelock RelativeTimelock `json:"relative_timelock"`
}

// VinPrevout contains information about the output being spent.
type VinPrevout struct {
	ValueSats       uint64 `json:"value_sats"`
	ScriptPubkeyHex string `json:"script_pubkey_hex"`
}

// RelativeTimelock represents BIP68 relative timelock state.
type RelativeTimelock struct {
	Enabled bool    `json:"enabled"`
	Type    *string `json:"type,omitempty"`  // "blocks" or "time", omit when disabled
	Value   *uint32 `json:"value,omitempty"` // blocks or seconds, omit when disabled
}

// InputScriptType constants for input classification.
const (
	InputScriptTypeP2PKH        = "p2pkh"
	InputScriptTypeP2SH_P2WPKH  = "p2sh-p2wpkh"
	InputScriptTypeP2SH_P2WSH   = "p2sh-p2wsh"
	InputScriptTypeP2WPKH       = "p2wpkh"
	InputScriptTypeP2WSH        = "p2wsh"
	InputScriptTypeP2TR_Keypath = "p2tr_keypath"
	InputScriptTypeP2TR_Script  = "p2tr_scriptpath"
	InputScriptTypeUnknown      = "unknown"
)

// RelativeTimelockType constants.
const (
	RelativeTimelockBlocks = "blocks"
	RelativeTimelockTime   = "time"
)

// BIP68 constants for sequence number interpretation.
const (
	// Bit 31: If set, relative timelock is disabled.
	SequenceLocktimeDisableFlag uint32 = 1 << 31

	// Bit 22: If set in lower 24 bits, interpret as time; otherwise as blocks.
	SequenceLocktimeTypeFlag uint32 = 1 << 22

	// Mask for the actual value (lower 16 bits).
	SequenceLocktimeMask uint32 = 0x0000FFFF

	// Time granularity: each unit = 512 seconds.
	SequenceLocktimeGranularity uint32 = 512
)

// Sequence values for RBF detection.
const (
	// Final sequence (no RBF, no relative timelock).
	SequenceFinal uint32 = 0xFFFFFFFF

	// Sequence that explicitly signals RBF.
	SequenceRBF uint32 = 0xFFFFFFFD
)
