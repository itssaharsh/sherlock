// Package models defines JSON output schema for Chain Lens block analysis.
package models

// BlockResult is the top-level JSON output for block-mode analysis.
type BlockResult struct {
	OK   bool   `json:"ok"`
	Mode string `json:"mode"` // "block"

	// Block header information
	BlockHeader BlockHeader `json:"block_header"`

	// Transaction count
	TxCount int `json:"tx_count"`

	// Coinbase transaction info
	Coinbase CoinbaseInfo `json:"coinbase"`

	// All transactions (same format as single-tx analysis)
	Transactions []TransactionResult `json:"transactions"`

	// Aggregated block statistics
	BlockStats BlockStats `json:"block_stats"`
}

// BlockHeader contains the parsed 80-byte block header.
type BlockHeader struct {
	Version         int32  `json:"version"`
	PrevBlockHash   string `json:"prev_block_hash"`
	MerkleRoot      string `json:"merkle_root"`
	MerkleRootValid bool   `json:"merkle_root_valid"`
	Timestamp       uint32 `json:"timestamp"`
	Bits            string `json:"bits"` // hex string of 4-byte compact difficulty
	Nonce           uint32 `json:"nonce"`
	BlockHash       string `json:"block_hash"`
}

// CoinbaseInfo contains information about the coinbase transaction.
type CoinbaseInfo struct {
	BIP34Height       int64  `json:"bip34_height"`
	CoinbaseScriptHex string `json:"coinbase_script_hex"`
	TotalOutputSats   uint64 `json:"total_output_sats"`
}

// BlockStats contains aggregated statistics for the block.
type BlockStats struct {
	TotalFeesSats     uint64            `json:"total_fees_sats"`
	TotalWeight       int               `json:"total_weight"`
	AvgFeeRateSatVB   float64           `json:"avg_fee_rate_sat_vb"`
	ScriptTypeSummary ScriptTypeSummary `json:"script_type_summary"`
}

// ScriptTypeSummary counts outputs by script type across all block transactions.
type ScriptTypeSummary struct {
	P2WPKH   int `json:"p2wpkh"`
	P2TR     int `json:"p2tr"`
	P2SH     int `json:"p2sh"`
	P2PKH    int `json:"p2pkh"`
	P2WSH    int `json:"p2wsh"`
	OPReturn int `json:"op_return"`
	Unknown  int `json:"unknown"`
}

// Block header constants.
const (
	// Block header size in bytes.
	BlockHeaderSize = 80

	// Block mode identifier.
	ModeBlock = "block"
)

// Coinbase input constants.
const (
	// Coinbase input txid is all zeros (32 bytes).
	CoinbaseTxid = "0000000000000000000000000000000000000000000000000000000000000000"

	// Coinbase input vout is 0xFFFFFFFF.
	CoinbaseVout uint32 = 0xFFFFFFFF
)

// UndoData represents a single undo record for an input's prevout.
type UndoData struct {
	Height          int64  // Coinbase height, or 0 for non-coinbase
	IsCoinbase      bool   // Whether the prevout was from a coinbase tx
	ValueSats       uint64 // Value of the prevout
	ScriptPubkeyHex string // Script pubkey of the prevout
}

// Undo compression types (nSize values).
const (
	// nSize 0: P2PKH (20-byte pubkey hash)
	UndoCompressP2PKH = 0
	// nSize 1: P2SH (20-byte script hash)
	UndoCompressP2SH = 1
	// nSize 2,3: Compressed public key (even/odd y)
	UndoCompressP2PKEven = 2
	UndoCompressP2PKOdd  = 3
	// nSize 4,5: Uncompressed public key (legacy)
	UndoCompressUncompEven = 4
	UndoCompressUncompOdd  = 5
	// nSize >= 6: Raw script (size = nSize - 6)
	UndoCompressRawScriptOffset = 6
)
