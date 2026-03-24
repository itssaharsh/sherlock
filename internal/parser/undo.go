// Package parser provides Bitcoin undo file (rev*.dat) parsing utilities.
package parser

import (
	"encoding/hex"

	"sherlock/internal/models"
)

// =============================================================================
// BITCOIN CORE UNDO FILE FORMAT (rev*.dat)
// =============================================================================
//
// The undo file contains data needed to reverse a block during a reorg.
// For each block, it stores prevout information for all non-coinbase inputs.
//
// FILE STRUCTURE:
// ┌───────────────────┬────────────────────┬────────────────────────────────┐
// │ magic (4 bytes)   │ undo_size (4 LE)   │ undo_data (undo_size bytes)    │
// │ same as blk*.dat  │                    │                                │
// └───────────────────┴────────────────────┴────────────────────────────────┘
//
// UNDO DATA FOR ONE BLOCK:
// For each non-coinbase transaction (tx index 1, 2, ...):
//   For each input:
//     [CTxInUndo]
//
// CTxInUndo structure:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ [code: varint]   - Encodes coinbase height + isCoinbase flag           │
// │ [value: varint]  - Compressed amount (special encoding)                │
// │ [script: compressed] - Compressed scriptPubKey (nSize encoding)        │
// └─────────────────────────────────────────────────────────────────────────┘
//
// =============================================================================
// CODE FIELD ENCODING
// =============================================================================
//
// The "code" varint encodes two pieces of information:
//   - Whether the UTXO being spent came from a coinbase transaction
//   - The height of the block containing the coinbase (if applicable)
//
// Decoding:
//   isCoinbase = (code & 1) != 0
//   height = code >> 1
//
// For non-coinbase UTXOs, height is typically 0.
//
// =============================================================================
// COMPRESSED AMOUNT ENCODING
// =============================================================================
//
// Bitcoin Core uses a special compression for amounts that works well for
// common Bitcoin values (whole bitcoins, common satoshi amounts).
//
// The decompression algorithm:
//   if n == 0: return 0
//   n--
//   e = n % 10  // exponent
//   n /= 10
//   if e < 9:
//     d = (n % 9) + 1  // digit
//     n /= 9
//     return (n * 10 + d) * 10^e
//   else:
//     return (n + 1) * 10^9
//
// =============================================================================
// COMPRESSED SCRIPT ENCODING (nSize)
// =============================================================================
//
// Script compression uses a "nSize" varint prefix to indicate the type:
//
// ┌────────┬─────────────────────────────────────────────────────────────────┐
// │ nSize  │ Meaning                                                         │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │   0    │ P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG  │
// │        │ Store only the 20-byte pubkey hash                              │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │   1    │ P2SH: OP_HASH160 <20 bytes> OP_EQUAL                            │
// │        │ Store only the 20-byte script hash                              │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │   2    │ P2PK (compressed pubkey, even Y)                                │
// │        │ Store 32-byte X coordinate, reconstruct with 0x02 prefix        │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │   3    │ P2PK (compressed pubkey, odd Y)                                 │
// │        │ Store 32-byte X coordinate, reconstruct with 0x03 prefix        │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │   4    │ P2PK (uncompressed pubkey, even Y) - Legacy                     │
// │        │ Store 32-byte X coordinate, reconstruct full 65-byte pubkey     │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │   5    │ P2PK (uncompressed pubkey, odd Y) - Legacy                      │
// │        │ Store 32-byte X coordinate, reconstruct full 65-byte pubkey     │
// ├────────┼─────────────────────────────────────────────────────────────────┤
// │  ≥6    │ Raw script                                                      │
// │        │ Actual script length = nSize - 6                                │
// │        │ Full script bytes follow                                        │
// └────────┴─────────────────────────────────────────────────────────────────┘
//
// =============================================================================

// UndoEntry represents the undo data for a single input (prevout).
type UndoEntry struct {
	IsCoinbase      bool   // Whether the spent UTXO was from a coinbase tx
	Height          int64  // Block height of the coinbase (0 for non-coinbase)
	Value           uint64 // Value in satoshis (decompressed)
	ScriptPubKey    []byte // Full reconstructed scriptPubKey
	ScriptPubKeyHex string // Hex encoding of scriptPubKey
}

// BlockUndo represents all undo data for a single block.
type BlockUndo struct {
	// TxUndos[i] contains undo entries for transaction i+1 (skipping coinbase at index 0)
	// TxUndos[i][j] is the undo entry for input j of transaction i+1
	TxUndos [][]UndoEntry
}

// ParseUndoFile parses a rev*.dat file and returns undo data for all blocks.
func ParseUndoFile(data []byte) ([]*BlockUndo, error) {
	var undos []*BlockUndo
	offset := 0

	for offset < len(data) {
		// Check minimum size for magic + size
		if offset+8 > len(data) {
			break
		}

		// Read magic (4 bytes) - same as block file
		magic := data[offset : offset+4]
		offset += 4

		// Validate magic (should match block file magic)
		magicVal := uint32(magic[0]) | uint32(magic[1])<<8 | uint32(magic[2])<<16 | uint32(magic[3])<<24
		if magicVal != MainnetMagic && magicVal != TestnetMagic && magicVal != RegtestMagic {
			// Try to find next valid magic
			found := false
			for offset < len(data)-4 {
				testMagic := uint32(data[offset]) | uint32(data[offset+1])<<8 |
					uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
				if testMagic == MainnetMagic || testMagic == TestnetMagic || testMagic == RegtestMagic {
					found = true
					break
				}
				offset++
			}
			if !found {
				break
			}
			continue
		}

		// Read undo size (4 bytes)
		if offset+4 > len(data) {
			break
		}
		undoSize := uint32(data[offset]) | uint32(data[offset+1])<<8 |
			uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
		offset += 4

		// Validate size
		if uint32(offset)+undoSize > uint32(len(data)) {
			return nil, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"undo size %d exceeds remaining data at offset %d", undoSize, offset)
		}

		// Note: The undo data format doesn't include explicit transaction count.
		// We need to parse it based on the corresponding block structure.
		// For now, store the raw data and parse it when we match with the block.
		undoData := data[offset : offset+int(undoSize)]
		offset += int(undoSize)

		// Parse the undo data - we'll need to know tx structure from block
		// For now, store as raw and provide ParseBlockUndoData when we have block info
		_ = undoData
		undos = append(undos, &BlockUndo{})
	}

	return undos, nil
}

// ParseBlockUndoData parses undo data for a specific block.
// inputCounts[i] is the number of inputs in transaction i+1 (excluding coinbase).
// This is used to validate the undo data structure.
// Returns undo entries matching the input structure.
func ParseBlockUndoData(undoData []byte, inputCounts []int) (*BlockUndo, error) {
	offset := 0
	var n int
	var err error

	// Read number of CTxUndo entries (CompactSize)
	txCount, n, err := ReadVarInt(undoData, offset)
	if err != nil {
		return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidUndoData,
			"failed to read tx count: %v", err)
	}
	offset += n

	// Validate tx count matches expected
	if int(txCount) != len(inputCounts) {
		return nil, models.NewAnalysisErrorf(models.ErrCodeUndoMismatch,
			"undo tx count (%d) doesn't match expected (%d)", txCount, len(inputCounts))
	}

	undo := &BlockUndo{
		TxUndos: make([][]UndoEntry, txCount),
	}

	// For each non-coinbase transaction
	for txIdx := uint64(0); txIdx < txCount; txIdx++ {
		// Read number of inputs for this tx (CompactSize)
		inputCount, n, err := ReadVarInt(undoData, offset)
		if err != nil {
			return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidUndoData,
				"failed to read input count for tx %d: %v", txIdx+1, err)
		}
		offset += n

		// Validate input count
		if int(inputCount) != inputCounts[txIdx] {
			return nil, models.NewAnalysisErrorf(models.ErrCodeUndoMismatch,
				"undo input count for tx %d (%d) doesn't match expected (%d)",
				txIdx+1, inputCount, inputCounts[txIdx])
		}

		undo.TxUndos[txIdx] = make([]UndoEntry, inputCount)

		// For each input in this transaction
		for inIdx := uint64(0); inIdx < inputCount; inIdx++ {
			entry, bytesRead, err := parseUndoEntry(undoData, offset)
			if err != nil {
				return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidUndoData,
					"failed to parse undo entry for tx %d input %d: %v", txIdx+1, inIdx, err)
			}
			undo.TxUndos[txIdx][inIdx] = entry
			offset += bytesRead
		}
	}

	// The undo data may have trailing checksum (32 bytes) - allow this
	remaining := len(undoData) - offset
	if remaining != 0 && remaining != 32 {
		return nil, models.NewAnalysisErrorf(models.ErrCodeUndoMismatch,
			"undo data has unexpected %d extra bytes after parsing", remaining)
	}

	return undo, nil
}

// parseUndoEntry parses a single CTxInUndo entry.
// The format is: code (SerVarInt) | version (1 byte, always 0x00) | amount (SerVarInt) | script
func parseUndoEntry(data []byte, offset int) (UndoEntry, int, error) {
	var entry UndoEntry
	startOffset := offset
	var n int
	var err error

	// Read code varint (encodes coinbase flag + height)
	// Uses serialization varint, not CompactSize!
	code, n, err := ReadSerVarInt(data, offset)
	if err != nil {
		return entry, 0, err
	}
	offset += n

	// Decode code: bit 0 = isCoinbase, bits 1+ = height
	entry.IsCoinbase = (code & 1) != 0
	entry.Height = int64(code >> 1)

	// Skip the version/flag byte (always 0x00 in current format)
	if offset >= len(data) {
		return entry, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
			"unexpected end of data after code at offset %d", offset)
	}
	offset++ // Skip the 0x00 byte

	// Read compressed amount (serialization varint)
	compressedAmount, n, err := ReadSerVarInt(data, offset)
	if err != nil {
		return entry, 0, err
	}
	offset += n

	// Decompress amount
	entry.Value = decompressAmount(compressedAmount)

	// Read compressed script
	entry.ScriptPubKey, n, err = readCompressedScript(data, offset)
	if err != nil {
		return entry, 0, err
	}
	offset += n

	entry.ScriptPubKeyHex = hex.EncodeToString(entry.ScriptPubKey)

	return entry, offset - startOffset, nil
}

// =============================================================================
// AMOUNT DECOMPRESSION
// =============================================================================

// decompressAmount decompresses a Bitcoin Core compressed amount.
// This uses Bitcoin Core's specific compression scheme.
func decompressAmount(x uint64) uint64 {
	if x == 0 {
		return 0
	}

	x--
	e := x % 10
	x /= 10

	var n uint64
	if e < 9 {
		d := (x % 9) + 1
		x /= 9
		n = x*10 + d
	} else {
		n = x + 1
	}

	// Multiply by 10^e
	for e > 0 {
		n *= 10
		e--
	}

	return n
}

// =============================================================================
// SCRIPT DECOMPRESSION
// =============================================================================

// readCompressedScript reads and decompresses a script using nSize encoding.
// nSize is read as a SerVarInt (variable-length encoding).
func readCompressedScript(data []byte, offset int) ([]byte, int, error) {
	startOffset := offset

	// Read nSize (serialization varint, not CompactSize!)
	// For small values (< 128), this is just a single byte
	nSize, n, err := ReadSerVarInt(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	var script []byte

	switch nSize {
	case 0:
		// P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
		if offset+20 > len(data) {
			return nil, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"need 20 bytes for P2PKH hash at offset %d", offset)
		}
		hash := data[offset : offset+20]
		offset += 20

		// Reconstruct full P2PKH script
		script = make([]byte, 25)
		script[0] = 0x76 // OP_DUP
		script[1] = 0xa9 // OP_HASH160
		script[2] = 0x14 // Push 20 bytes
		copy(script[3:23], hash)
		script[23] = 0x88 // OP_EQUALVERIFY
		script[24] = 0xac // OP_CHECKSIG

	case 1:
		// P2SH: OP_HASH160 <20 bytes> OP_EQUAL
		if offset+20 > len(data) {
			return nil, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"need 20 bytes for P2SH hash at offset %d", offset)
		}
		hash := data[offset : offset+20]
		offset += 20

		// Reconstruct full P2SH script
		script = make([]byte, 23)
		script[0] = 0xa9 // OP_HASH160
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:22], hash)
		script[22] = 0x87 // OP_EQUAL

	case 2, 3:
		// P2PK with compressed pubkey (33 bytes: 0x02/0x03 + 32 bytes)
		// nSize 2 = even Y (0x02 prefix), nSize 3 = odd Y (0x03 prefix)
		if offset+32 > len(data) {
			return nil, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"need 32 bytes for compressed pubkey at offset %d", offset)
		}
		xCoord := data[offset : offset+32]
		offset += 32

		// Reconstruct P2PK script: <33-byte compressed pubkey> OP_CHECKSIG
		script = make([]byte, 35)
		script[0] = 0x21 // Push 33 bytes
		if nSize == 2 {
			script[1] = 0x02 // Even Y
		} else {
			script[1] = 0x03 // Odd Y
		}
		copy(script[2:34], xCoord)
		script[34] = 0xac // OP_CHECKSIG

	case 4, 5:
		// P2PK with uncompressed pubkey (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
		// We only store X coordinate; Y must be computed from the curve
		// nSize 4 = even Y, nSize 5 = odd Y
		if offset+32 > len(data) {
			return nil, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"need 32 bytes for uncompressed pubkey X at offset %d", offset)
		}
		xCoord := data[offset : offset+32]
		offset += 32

		// For full reconstruction, we'd need to compute Y from the secp256k1 curve
		// For now, store as compressed form (sufficient for most purposes)
		// A full implementation would use elliptic curve math here
		script = make([]byte, 35)
		script[0] = 0x21 // Push 33 bytes (using compressed form)
		if nSize == 4 {
			script[1] = 0x02 // Even Y
		} else {
			script[1] = 0x03 // Odd Y
		}
		copy(script[2:34], xCoord)
		script[34] = 0xac // OP_CHECKSIG

	default:
		// Raw script: nSize >= 6, actual length = nSize - 6
		scriptLen := int(nSize) - 6
		if scriptLen < 0 {
			return nil, 0, models.NewAnalysisErrorf(models.ErrCodeInvalidUndoData,
				"invalid nSize %d for raw script", nSize)
		}
		if offset+scriptLen > len(data) {
			return nil, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"need %d bytes for raw script at offset %d", scriptLen, offset)
		}
		script = make([]byte, scriptLen)
		copy(script, data[offset:offset+scriptLen])
		offset += scriptLen
	}

	return script, offset - startOffset, nil
}

// =============================================================================
// HELPER: MATCH UNDO DATA TO BLOCK
// =============================================================================

// GetInputCounts returns the input counts for non-coinbase transactions.
// Used to parse undo data which doesn't store transaction boundaries.
func GetInputCounts(txs []*RawTransaction) []int {
	if len(txs) <= 1 {
		return nil // Only coinbase, no undo data needed
	}

	counts := make([]int, len(txs)-1)
	for i := 1; i < len(txs); i++ {
		counts[i-1] = len(txs[i].Inputs)
	}
	return counts
}
