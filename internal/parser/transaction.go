// Package parser provides Bitcoin transaction and block parsing utilities.
package parser

import (
	"crypto/sha256"
	"encoding/hex"

	"sherlock/internal/models"
)

// =============================================================================
// BITCOIN TRANSACTION FORMAT
// =============================================================================
//
// LEGACY TRANSACTION (non-SegWit):
// ┌─────────────┬───────────────┬──────────┬────────────────┬──────────┬──────────┐
// │ version (4) │ input_count   │ inputs[] │ output_count   │ outputs[]│locktime(4)│
// │ little-end  │ (varint)      │          │ (varint)       │          │little-end│
// └─────────────┴───────────────┴──────────┴────────────────┴──────────┴──────────┘
//
// SEGWIT TRANSACTION (BIP141):
// ┌─────────────┬────────┬──────┬───────────────┬──────────┬────────────────┬──────────┬───────────┬──────────┐
// │ version (4) │marker  │flag  │ input_count   │ inputs[] │ output_count   │ outputs[]│ witness[] │locktime(4)│
// │ little-end  │(1)=0x00│(1)=01│ (varint)      │          │ (varint)       │          │           │little-end│
// └─────────────┴────────┴──────┴───────────────┴──────────┴────────────────┴──────────┴───────────┴──────────┘
//
// INPUT FORMAT (each input):
// ┌──────────────────┬───────────────┬────────────────────┬─────────────────┬──────────────┐
// │ prev_txid (32)   │ prev_vout (4) │ script_sig_len     │ script_sig      │ sequence (4) │
// │ little-endian    │ little-endian │ (varint)           │ (variable)      │ little-endian│
// └──────────────────┴───────────────┴────────────────────┴─────────────────┴──────────────┘
//
// OUTPUT FORMAT (each output):
// ┌──────────────────┬─────────────────────┬─────────────────────┐
// │ value (8)        │ script_pubkey_len   │ script_pubkey       │
// │ little-endian    │ (varint)            │ (variable)          │
// │ satoshis         │                     │                     │
// └──────────────────┴─────────────────────┴─────────────────────┘
//
// WITNESS FORMAT (for each input, if SegWit):
// ┌─────────────────┬───────────────────┬────────────────┬─────────────────┬───────┐
// │ item_count      │ item_0_len        │ item_0_data    │ item_1_len      │ ...   │
// │ (varint)        │ (varint)          │ (variable)     │ (varint)        │       │
// └─────────────────┴───────────────────┴────────────────┴─────────────────┴───────┘
// =============================================================================

// RawTransaction represents a fully parsed transaction with raw data preserved.
type RawTransaction struct {
	// Original raw bytes and hex
	Raw    []byte
	RawHex string

	// Parsed fields
	Version  int32
	Locktime uint32

	// SegWit detection
	IsSegwit bool
	Marker   byte // 0x00 for SegWit
	Flag     byte // 0x01 for SegWit

	// Parsed inputs and outputs
	Inputs  []RawInput
	Outputs []RawOutput

	// Witness data (one slice per input)
	Witnesses [][]RawWitnessItem

	// Size metrics for BIP141 weight calculation
	TotalSize      int // Total serialized size in bytes
	WitnessSize    int // Witness data size (marker + flag + witness stack)
	NonWitnessSize int // Non-witness size (everything else)
}

// RawInput represents a transaction input.
type RawInput struct {
	PrevTxid  [32]byte // Previous transaction hash (internal little-endian)
	PrevVout  uint32   // Previous output index
	ScriptSig []byte   // Unlocking script (scriptSig)
	Sequence  uint32   // Sequence number
}

// RawOutput represents a transaction output.
type RawOutput struct {
	Value        uint64 // Value in satoshis
	ScriptPubkey []byte // Locking script (scriptPubKey)
}

// RawWitnessItem is a single witness stack item (raw bytes).
type RawWitnessItem []byte

// =============================================================================
// MAIN PARSING FUNCTION
// =============================================================================

// ParseTransaction parses a raw transaction from hex string.
// This is the main entry point for transaction parsing.
func ParseTransaction(rawHex string) (*RawTransaction, error) {
	// Step 1: Decode hex to bytes
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidHex,
			"invalid hex encoding: %v", err)
	}

	return ParseTransactionBytes(raw)
}

// ParseTransactionBytes parses a raw transaction from bytes.
func ParseTransactionBytes(raw []byte) (*RawTransaction, error) {
	if len(raw) < 10 {
		return nil, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"transaction too short: %d bytes (minimum ~10)", len(raw))
	}

	tx := &RawTransaction{
		Raw:    raw,
		RawHex: hex.EncodeToString(raw),
	}

	offset := 0
	var n int
	var err error

	// =========================================================================
	// STEP 1: Read Version (4 bytes, little-endian int32)
	// =========================================================================
	// Offset: 0-3
	// Example: [02 00 00 00] = version 2
	tx.Version, n, err = ReadInt32LE(raw, offset)
	if err != nil {
		return nil, err
	}
	offset += n

	// =========================================================================
	// STEP 2: Detect SegWit by checking for marker (0x00) and flag (0x01)
	// =========================================================================
	// In SegWit transactions, bytes 4-5 are [0x00, 0x01]
	// In legacy transactions, byte 4 is the input count (varint), which is
	// never 0x00 (a transaction must have at least 1 input).
	//
	// Detection logic:
	//   - If byte[4] == 0x00 AND byte[5] == 0x01 -> SegWit
	//   - Otherwise -> Legacy
	tx.IsSegwit = false
	if offset+2 <= len(raw) && raw[offset] == 0x00 && raw[offset+1] == 0x01 {
		tx.IsSegwit = true
		tx.Marker = raw[offset]
		tx.Flag = raw[offset+1]
		offset += 2 // Skip marker and flag
	}

	// =========================================================================
	// STEP 3: Read Input Count (varint)
	// =========================================================================
	inputCount, n, err := ReadVarInt(raw, offset)
	if err != nil {
		return nil, err
	}
	offset += n

	if inputCount == 0 {
		return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
			"transaction has 0 inputs")
	}

	// =========================================================================
	// STEP 4: Parse Each Input
	// =========================================================================
	tx.Inputs = make([]RawInput, inputCount)
	for i := uint64(0); i < inputCount; i++ {
		input, bytesRead, err := parseInput(raw, offset)
		if err != nil {
			return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
				"failed to parse input %d: %v", i, err)
		}
		tx.Inputs[i] = input
		offset += bytesRead
	}

	// =========================================================================
	// STEP 5: Read Output Count (varint)
	// =========================================================================
	outputCount, n, err := ReadVarInt(raw, offset)
	if err != nil {
		return nil, err
	}
	offset += n

	// =========================================================================
	// STEP 6: Parse Each Output
	// =========================================================================
	tx.Outputs = make([]RawOutput, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		output, bytesRead, err := parseOutput(raw, offset)
		if err != nil {
			return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
				"failed to parse output %d: %v", i, err)
		}
		tx.Outputs[i] = output
		offset += bytesRead
	}

	// =========================================================================
	// STEP 7: Parse Witness Data (if SegWit)
	// =========================================================================
	witnessStartOffset := offset
	if tx.IsSegwit {
		tx.Witnesses = make([][]RawWitnessItem, inputCount)
		for i := uint64(0); i < inputCount; i++ {
			witness, bytesRead, err := parseWitness(raw, offset)
			if err != nil {
				return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidWitness,
					"failed to parse witness for input %d: %v", i, err)
			}
			tx.Witnesses[i] = witness
			offset += bytesRead
		}
	} else {
		// Legacy transactions have no witness data
		tx.Witnesses = make([][]RawWitnessItem, inputCount)
		for i := range tx.Witnesses {
			tx.Witnesses[i] = []RawWitnessItem{} // Empty witness stack
		}
	}
	witnessEndOffset := offset

	// =========================================================================
	// STEP 8: Read Locktime (4 bytes, little-endian uint32)
	// =========================================================================
	tx.Locktime, n, err = ReadUint32LE(raw, offset)
	if err != nil {
		return nil, err
	}
	offset += n

	// =========================================================================
	// STEP 9: Verify we consumed exactly all bytes
	// =========================================================================
	if offset != len(raw) {
		return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
			"transaction has %d extra bytes after parsing", len(raw)-offset)
	}

	// =========================================================================
	// STEP 10: Calculate Size Metrics (BIP141)
	// =========================================================================
	tx.TotalSize = len(raw)

	if tx.IsSegwit {
		// Witness size = marker(1) + flag(1) + all witness data
		tx.WitnessSize = 2 + (witnessEndOffset - witnessStartOffset)
		tx.NonWitnessSize = tx.TotalSize - tx.WitnessSize
	} else {
		tx.WitnessSize = 0
		tx.NonWitnessSize = tx.TotalSize
	}

	return tx, nil
}

// =============================================================================
// INPUT PARSING
// =============================================================================

// parseInput parses a single transaction input starting at offset.
// Returns (input, bytesRead, error).
//
// Input structure:
//
//	[prev_txid: 32 bytes] [prev_vout: 4 bytes] [script_len: varint] [script: N bytes] [sequence: 4 bytes]
func parseInput(data []byte, offset int) (RawInput, int, error) {
	var input RawInput
	startOffset := offset
	var n int
	var err error

	// -------------------------------------------------------------------------
	// Read Previous Transaction ID (32 bytes)
	// -------------------------------------------------------------------------
	// Stored in internal byte order (little-endian), which is reversed
	// from the display format. When displaying, we reverse and hex-encode.
	if offset+32 > len(data) {
		return input, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"input: need 32 bytes for prev_txid at offset %d", offset)
	}
	copy(input.PrevTxid[:], data[offset:offset+32])
	offset += 32

	// -------------------------------------------------------------------------
	// Read Previous Output Index (4 bytes, little-endian uint32)
	// -------------------------------------------------------------------------
	input.PrevVout, n, err = ReadUint32LE(data, offset)
	if err != nil {
		return input, 0, err
	}
	offset += n

	// -------------------------------------------------------------------------
	// Read ScriptSig Length (varint)
	// -------------------------------------------------------------------------
	scriptLen, n, err := ReadVarInt(data, offset)
	if err != nil {
		return input, 0, err
	}
	offset += n

	// -------------------------------------------------------------------------
	// Read ScriptSig (variable length)
	// -------------------------------------------------------------------------
	input.ScriptSig, n, err = ReadBytes(data, offset, int(scriptLen))
	if err != nil {
		return input, 0, err
	}
	offset += n

	// -------------------------------------------------------------------------
	// Read Sequence Number (4 bytes, little-endian uint32)
	// -------------------------------------------------------------------------
	input.Sequence, n, err = ReadUint32LE(data, offset)
	if err != nil {
		return input, 0, err
	}
	offset += n

	return input, offset - startOffset, nil
}

// =============================================================================
// OUTPUT PARSING
// =============================================================================

// parseOutput parses a single transaction output starting at offset.
// Returns (output, bytesRead, error).
//
// Output structure:
//
//	[value: 8 bytes] [script_len: varint] [script: N bytes]
func parseOutput(data []byte, offset int) (RawOutput, int, error) {
	var output RawOutput
	startOffset := offset
	var n int
	var err error

	// -------------------------------------------------------------------------
	// Read Value (8 bytes, little-endian uint64)
	// -------------------------------------------------------------------------
	// Value is in satoshis (1 BTC = 100,000,000 satoshis)
	output.Value, n, err = ReadUint64LE(data, offset)
	if err != nil {
		return output, 0, err
	}
	offset += n

	// -------------------------------------------------------------------------
	// Read ScriptPubKey Length (varint)
	// -------------------------------------------------------------------------
	scriptLen, n, err := ReadVarInt(data, offset)
	if err != nil {
		return output, 0, err
	}
	offset += n

	// -------------------------------------------------------------------------
	// Read ScriptPubKey (variable length)
	// -------------------------------------------------------------------------
	output.ScriptPubkey, n, err = ReadBytes(data, offset, int(scriptLen))
	if err != nil {
		return output, 0, err
	}
	offset += n

	return output, offset - startOffset, nil
}

// =============================================================================
// WITNESS PARSING
// =============================================================================

// parseWitness parses the witness data for a single input starting at offset.
// Returns (witnessStack, bytesRead, error).
//
// Witness structure (per input):
//
//	[item_count: varint] [item_0_len: varint] [item_0: N bytes] [item_1_len: varint] [item_1: N bytes] ...
//
// Example P2WPKH witness (2 items):
//
//	[02]                          <- 2 items
//	[47] [3044...01]              <- item 0: 71-byte signature
//	[21] [03...]                  <- item 1: 33-byte compressed pubkey
func parseWitness(data []byte, offset int) ([]RawWitnessItem, int, error) {
	startOffset := offset
	var n int
	var err error

	// -------------------------------------------------------------------------
	// Read Witness Stack Item Count (varint)
	// -------------------------------------------------------------------------
	itemCount, n, err := ReadVarInt(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// -------------------------------------------------------------------------
	// Read Each Witness Item
	// -------------------------------------------------------------------------
	items := make([]RawWitnessItem, itemCount)
	for i := uint64(0); i < itemCount; i++ {
		// Read item length (varint)
		itemLen, n, err := ReadVarInt(data, offset)
		if err != nil {
			return nil, 0, err
		}
		offset += n

		// Read item data
		itemData, n, err := ReadBytes(data, offset, int(itemLen))
		if err != nil {
			return nil, 0, err
		}
		offset += n

		items[i] = RawWitnessItem(itemData)
	}

	return items, offset - startOffset, nil
}

// =============================================================================
// TRANSACTION ID CALCULATION
// =============================================================================

// Txid calculates the transaction ID (txid).
// For both legacy and SegWit transactions, txid is the double-SHA256 of
// the "traditional" serialization (without witness data).
//
// Traditional serialization:
//
//	[version] [input_count] [inputs...] [output_count] [outputs...] [locktime]
//
// Result is reversed and hex-encoded (Bitcoin display convention).
func (tx *RawTransaction) Txid() string {
	traditional := tx.serializeTraditional()
	hash := doubleSHA256(traditional)
	return reverseHex(hash[:])
}

// Wtxid calculates the witness transaction ID (wtxid).
// For SegWit transactions, wtxid is the double-SHA256 of the full serialization
// including witness data.
// For legacy transactions, wtxid == txid.
// Returns nil for non-SegWit transactions per spec.
func (tx *RawTransaction) Wtxid() *string {
	if !tx.IsSegwit {
		return nil // Per spec: wtxid must be null for non-SegWit
	}

	// For SegWit, wtxid is hash of full serialization including witness
	hash := doubleSHA256(tx.Raw)
	wtxid := reverseHex(hash[:])
	return &wtxid
}

// serializeTraditional creates the traditional (non-witness) serialization.
// This excludes the marker, flag, and witness data.
func (tx *RawTransaction) serializeTraditional() []byte {
	if !tx.IsSegwit {
		// Legacy transaction: raw bytes are already traditional format
		return tx.Raw
	}

	// For SegWit, reconstruct without marker/flag/witness:
	// [version(4)] + [inputs] + [outputs] + [locktime(4)]
	buf := make([]byte, tx.NonWitnessSize)
	offset := 0

	// Copy version (first 4 bytes)
	copy(buf[offset:], tx.Raw[0:4])
	offset += 4

	// Skip marker and flag in source, copy from byte 6 onward
	// We need to copy everything except:
	// - bytes 4-5 (marker + flag)
	// - witness data (which comes after outputs, before locktime)

	// Find where inputs+outputs end in the original (before witness)
	// This is NonWitnessSize - 4 (version) - 4 (locktime) = inputs + outputs size
	inputOutputSize := tx.NonWitnessSize - 8

	// Copy inputs and outputs (skip marker/flag at bytes 4-5)
	copy(buf[offset:], tx.Raw[6:6+inputOutputSize])
	offset += inputOutputSize

	// Copy locktime (last 4 bytes of original)
	copy(buf[offset:], tx.Raw[len(tx.Raw)-4:])

	return buf
}

// doubleSHA256 computes SHA256(SHA256(data)).
func doubleSHA256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// =============================================================================
// BIP141 WEIGHT AND VBYTES CALCULATION
// =============================================================================
//
// BIP141 defines "weight" for fee calculation:
//
//	weight = (non-witness size * 4) + (witness size * 1)
//	vbytes = ceil(weight / 4)
//
// For legacy transactions (no witness):
//
//	weight = total_size * 4
//	vbytes = total_size
//
// For SegWit transactions:
//   - Non-witness bytes: version + inputs + outputs + locktime
//   - Witness bytes: marker + flag + witness stack
//   - Witness data gets 75% discount (weight 1 instead of 4)
//
// Example:
//
//	Legacy 250 bytes:  weight = 250 * 4 = 1000, vbytes = 250
//	SegWit 250 bytes (150 non-witness + 100 witness):
//	  weight = (150 * 4) + (100 * 1) = 700
//	  vbytes = ceil(700 / 4) = 175

// Weight returns the transaction weight in weight units (WU).
func (tx *RawTransaction) Weight() int {
	return (tx.NonWitnessSize * 4) + (tx.WitnessSize * 1)
}

// Vbytes returns the virtual size in virtual bytes.
// This is the value used for fee rate calculation.
func (tx *RawTransaction) Vbytes() int {
	weight := tx.Weight()
	// Ceiling division: (weight + 3) / 4
	return (weight + 3) / 4
}

// WeightIfLegacy returns what the weight would be if this were a legacy tx.
// Used for SegWit savings calculation.
func (tx *RawTransaction) WeightIfLegacy() int {
	return tx.TotalSize * 4
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// OutPointKey returns the (txid, vout) lookup key for an input.
func (r *RawInput) OutPointKey() models.OutPoint {
	// Convert internal little-endian to display hex (reverse bytes)
	txidHex := reverseHex(r.PrevTxid[:])
	return models.OutPoint{
		Txid: txidHex,
		Vout: r.PrevVout,
	}
}

// reverseHex reverses a byte slice and encodes as hex.
func reverseHex(b []byte) string {
	reversed := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		reversed[i] = b[len(b)-1-i]
	}
	return hex.EncodeToString(reversed)
}

// ReverseBytes reverses a byte slice in place.
func ReverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
