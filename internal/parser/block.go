// Package parser provides Bitcoin block parsing utilities.
package parser

import (
	"encoding/binary"
	"encoding/hex"

	"sherlock/internal/models"
)

// =============================================================================
// BITCOIN BLOCK FILE FORMAT (blk*.dat)
// =============================================================================
//
// Each block in the file is prefixed with:
//
// ┌───────────────────┬────────────────────┬────────────────────────────────┐
// │ magic (4 bytes)   │ block_size (4 LE)  │ block_data (block_size bytes)  │
// │ 0xF9BEB4D9        │ size of block data │ header + txcount + txs         │
// └───────────────────┴────────────────────┴────────────────────────────────┘
//
// Block data structure:
// ┌──────────────────┬─────────────────┬──────────────────────────────────────┐
// │ header (80 bytes)│ tx_count(varint)│ transactions[]                       │
// └──────────────────┴─────────────────┴──────────────────────────────────────┘
//
// Block header (80 bytes):
// ┌─────────────┬──────────────────┬───────────────┬───────────┬──────────┬──────────┐
// │ version (4) │ prev_block (32)  │ merkle_root   │ timestamp │ bits (4) │ nonce(4) │
// │ LE int32    │ LE hash          │ (32) LE hash  │ (4) LE    │ target   │ LE uint32│
// └─────────────┴──────────────────┴───────────────┴───────────┴──────────┴──────────┘
//
// Network magic bytes:
//   Mainnet:  0xF9BEB4D9
//   Testnet:  0x0B110907
//   Regtest:  0xFABFB5DA
// =============================================================================

// Network magic bytes
const (
	MainnetMagic = 0xD9B4BEF9 // Little-endian: F9 BE B4 D9
	TestnetMagic = 0x0709110B // Little-endian: 0B 11 09 07
	RegtestMagic = 0xDAB5BFFA // Little-endian: FA BF B5 DA
)

// BlockHeaderSize is the size of a block header in bytes.
const BlockHeaderSize = 80

// RawBlockHeader represents a parsed 80-byte block header.
type RawBlockHeader struct {
	Version       int32    // Block version
	PrevBlockHash [32]byte // Hash of previous block (internal byte order)
	MerkleRoot    [32]byte // Merkle root of transactions (internal byte order)
	Timestamp     uint32   // Unix timestamp
	Bits          uint32   // Compact difficulty target
	Nonce         uint32   // Nonce for PoW
}

// RawBlock represents a fully parsed block.
type RawBlock struct {
	Header       RawBlockHeader
	Transactions []*RawTransaction
}

// =============================================================================
// BLOCK HEADER PARSING
// =============================================================================

// ParseBlockHeader parses an 80-byte block header.
//
// Byte layout:
//   Offset 0-3:   Version (little-endian int32)
//   Offset 4-35:  Previous block hash (32 bytes, internal byte order)
//   Offset 36-67: Merkle root (32 bytes, internal byte order)
//   Offset 68-71: Timestamp (little-endian uint32)
//   Offset 72-75: Bits (little-endian uint32, compact difficulty)
//   Offset 76-79: Nonce (little-endian uint32)
func ParseBlockHeader(data []byte) (*RawBlockHeader, error) {
	if len(data) < BlockHeaderSize {
		return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidBlockHeader,
			"block header too short: %d bytes (need %d)", len(data), BlockHeaderSize)
	}

	header := &RawBlockHeader{}

	// Version (bytes 0-3)
	header.Version = int32(binary.LittleEndian.Uint32(data[0:4]))

	// Previous block hash (bytes 4-35)
	copy(header.PrevBlockHash[:], data[4:36])

	// Merkle root (bytes 36-67)
	copy(header.MerkleRoot[:], data[36:68])

	// Timestamp (bytes 68-71)
	header.Timestamp = binary.LittleEndian.Uint32(data[68:72])

	// Bits (bytes 72-75)
	header.Bits = binary.LittleEndian.Uint32(data[72:76])

	// Nonce (bytes 76-79)
	header.Nonce = binary.LittleEndian.Uint32(data[76:80])

	return header, nil
}

// BlockHash computes the block hash (double SHA256 of header).
// Returns the hash in display format (reversed hex).
func (h *RawBlockHeader) BlockHash() string {
	// Serialize header to 80 bytes
	headerBytes := h.Serialize()

	// Double SHA256
	hash := doubleSHA256(headerBytes)

	// Return reversed hex (display format)
	return reverseHex(hash[:])
}

// Serialize serializes the block header to 80 bytes.
func (h *RawBlockHeader) Serialize() []byte {
	buf := make([]byte, BlockHeaderSize)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(h.Version))
	copy(buf[4:36], h.PrevBlockHash[:])
	copy(buf[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint32(buf[68:72], h.Timestamp)
	binary.LittleEndian.PutUint32(buf[72:76], h.Bits)
	binary.LittleEndian.PutUint32(buf[76:80], h.Nonce)

	return buf
}

// PrevBlockHashHex returns the previous block hash in display format.
func (h *RawBlockHeader) PrevBlockHashHex() string {
	return reverseHex(h.PrevBlockHash[:])
}

// MerkleRootHex returns the merkle root in display format.
func (h *RawBlockHeader) MerkleRootHex() string {
	return reverseHex(h.MerkleRoot[:])
}

// BitsHex returns the bits field as hex string.
func (h *RawBlockHeader) BitsHex() string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, h.Bits)
	return hex.EncodeToString(buf)
}

// =============================================================================
// MERKLE ROOT CALCULATION
// =============================================================================
//
// The Merkle root is computed from transaction IDs (txids) using a binary tree:
//
//        Merkle Root
//           /   \
//          /     \
//       H(AB)   H(CD)
//       /  \     /  \
//      A    B   C    D   (txids)
//
// If odd number of leaves, the last one is duplicated.
// Each level: H(left || right) where H = double-SHA256
// =============================================================================

// ComputeMerkleRoot computes the Merkle root from a list of transaction hashes.
// The hashes should be in internal byte order (not display format).
func ComputeMerkleRoot(txHashes [][32]byte) [32]byte {
	if len(txHashes) == 0 {
		return [32]byte{}
	}

	// Make a copy to avoid modifying the original
	hashes := make([][32]byte, len(txHashes))
	copy(hashes, txHashes)

	// Build tree bottom-up
	for len(hashes) > 1 {
		// If odd number, duplicate the last hash
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		// Compute next level
		nextLevel := make([][32]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			// Concatenate left and right, then double-SHA256
			var combined [64]byte
			copy(combined[0:32], hashes[i][:])
			copy(combined[32:64], hashes[i+1][:])
			nextLevel[i/2] = doubleSHA256(combined[:])
		}
		hashes = nextLevel
	}

	return hashes[0]
}

// ComputeMerkleRootFromTxids computes the Merkle root from transaction IDs.
// txids should be in display format (hex strings, reversed).
func ComputeMerkleRootFromTxids(txids []string) ([32]byte, error) {
	hashes := make([][32]byte, len(txids))

	for i, txid := range txids {
		// Convert from display format (reversed) to internal byte order
		decoded, err := hex.DecodeString(txid)
		if err != nil {
			return [32]byte{}, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
				"invalid txid hex: %s", txid)
		}
		if len(decoded) != 32 {
			return [32]byte{}, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
				"invalid txid length: %d", len(decoded))
		}

		// Reverse to internal byte order
		for j := 0; j < 32; j++ {
			hashes[i][j] = decoded[31-j]
		}
	}

	return ComputeMerkleRoot(hashes), nil
}

// GetTxidHash returns the txid as internal byte order hash (for merkle computation).
func (tx *RawTransaction) GetTxidHash() [32]byte {
	traditional := tx.serializeTraditional()
	return doubleSHA256(traditional)
}

// =============================================================================
// BLOCK FILE PARSING
// =============================================================================

// BlockFileEntry represents a single block entry in a blk*.dat file.
type BlockFileEntry struct {
	Magic     uint32
	BlockSize uint32
	Header    *RawBlockHeader
	RawData   []byte // Full block data (header + txs)
	Offset    int64  // File offset where this block starts
}

// ParseBlockFile reads all blocks from a blk*.dat file.
// Returns the blocks in order as they appear in the file.
func ParseBlockFile(data []byte) ([]*BlockFileEntry, error) {
	var blocks []*BlockFileEntry
	offset := 0

	for offset < len(data) {
		// Check for minimum size (magic + size + header)
		if offset+8+BlockHeaderSize > len(data) {
			// Not enough data for another block, we're done
			break
		}

		// Read magic (4 bytes)
		magic := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		// Validate magic number
		if magic != MainnetMagic && magic != TestnetMagic && magic != RegtestMagic {
			// Could be padding or end of file
			// Skip to find next magic
			found := false
			for offset < len(data)-4 {
				testMagic := binary.LittleEndian.Uint32(data[offset : offset+4])
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

		// Read block size (4 bytes)
		if offset+4 > len(data) {
			break
		}
		blockSize := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		// Validate block size
		if uint32(offset)+blockSize > uint32(len(data)) {
			return nil, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
				"block size %d exceeds remaining data at offset %d", blockSize, offset)
		}

		// Read block data
		blockData := data[offset : offset+int(blockSize)]

		// Parse header
		header, err := ParseBlockHeader(blockData)
		if err != nil {
			return nil, err
		}

		entry := &BlockFileEntry{
			Magic:     magic,
			BlockSize: blockSize,
			Header:    header,
			RawData:   blockData,
			Offset:    int64(offset - 8), // Offset includes magic and size
		}

		blocks = append(blocks, entry)
		offset += int(blockSize)
	}

	return blocks, nil
}

// ParseBlockTransactions parses all transactions from block data.
// blockData should start with the 80-byte header.
func ParseBlockTransactions(blockData []byte) ([]*RawTransaction, error) {
	if len(blockData) < BlockHeaderSize {
		return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidBlockHeader,
			"block data too short for header")
	}

	offset := BlockHeaderSize

	// Read transaction count
	txCount, n, err := ReadVarInt(blockData, offset)
	if err != nil {
		return nil, err
	}
	offset += n

	// Parse each transaction
	txs := make([]*RawTransaction, txCount)
	for i := uint64(0); i < txCount; i++ {
		// Find where this transaction ends
		// We need to parse it to know its length
		txStart := offset

		// Parse transaction starting at offset
		// We need to find the end, so parse incrementally
		tx, bytesConsumed, err := parseTransactionFromBlock(blockData, offset)
		if err != nil {
			return nil, models.NewAnalysisErrorf(models.ErrCodeInvalidTx,
				"failed to parse transaction %d: %v", i, err)
		}

		// Set the raw bytes
		tx.Raw = blockData[txStart : txStart+bytesConsumed]
		tx.RawHex = hex.EncodeToString(tx.Raw)

		txs[i] = tx
		offset += bytesConsumed
	}

	return txs, nil
}

// parseTransactionFromBlock parses a transaction from block data starting at offset.
// Returns the transaction and number of bytes consumed.
func parseTransactionFromBlock(data []byte, startOffset int) (*RawTransaction, int, error) {
	tx := &RawTransaction{}
	offset := startOffset
	var n int
	var err error

	// Version (4 bytes)
	tx.Version, n, err = ReadInt32LE(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// Check for SegWit marker/flag
	tx.IsSegwit = false
	if offset+2 <= len(data) && data[offset] == 0x00 && data[offset+1] == 0x01 {
		tx.IsSegwit = true
		tx.Marker = data[offset]
		tx.Flag = data[offset+1]
		offset += 2
	}

	// Input count
	inputCount, n, err := ReadVarInt(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// Parse inputs
	tx.Inputs = make([]RawInput, inputCount)
	for i := uint64(0); i < inputCount; i++ {
		input, bytesRead, err := parseInput(data, offset)
		if err != nil {
			return nil, 0, err
		}
		tx.Inputs[i] = input
		offset += bytesRead
	}

	// Output count
	outputCount, n, err := ReadVarInt(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// Parse outputs
	tx.Outputs = make([]RawOutput, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		output, bytesRead, err := parseOutput(data, offset)
		if err != nil {
			return nil, 0, err
		}
		tx.Outputs[i] = output
		offset += bytesRead
	}

	// Witness data
	witnessStart := offset
	if tx.IsSegwit {
		tx.Witnesses = make([][]RawWitnessItem, inputCount)
		for i := uint64(0); i < inputCount; i++ {
			witness, bytesRead, err := parseWitness(data, offset)
			if err != nil {
				return nil, 0, err
			}
			tx.Witnesses[i] = witness
			offset += bytesRead
		}
	} else {
		tx.Witnesses = make([][]RawWitnessItem, inputCount)
		for i := range tx.Witnesses {
			tx.Witnesses[i] = []RawWitnessItem{}
		}
	}
	witnessEnd := offset

	// Locktime (4 bytes)
	tx.Locktime, n, err = ReadUint32LE(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// Calculate sizes
	tx.TotalSize = offset - startOffset
	if tx.IsSegwit {
		tx.WitnessSize = 2 + (witnessEnd - witnessStart)
		tx.NonWitnessSize = tx.TotalSize - tx.WitnessSize
	} else {
		tx.WitnessSize = 0
		tx.NonWitnessSize = tx.TotalSize
	}

	return tx, offset - startOffset, nil
}
