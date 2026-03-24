// Package parser provides Bitcoin varint (CompactSize) utilities.
package parser

import (
	"encoding/binary"

	"sherlock/internal/models"
)

// Bitcoin uses "CompactSize" unsigned integers for variable-length encoding.
// Format:
//   - 0x00-0xFC: 1 byte  (value as-is)
//   - 0xFD:      3 bytes (0xFD + 2-byte little-endian uint16)
//   - 0xFE:      5 bytes (0xFE + 4-byte little-endian uint32)
//   - 0xFF:      9 bytes (0xFF + 8-byte little-endian uint64)

// ReadVarInt reads a Bitcoin CompactSize varint from data starting at offset.
// Returns (value, bytesRead, error).
//
// Example byte sequences:
//   [0x01]             -> value=1,   bytesRead=1
//   [0xFC]             -> value=252, bytesRead=1
//   [0xFD, 0x00, 0x01] -> value=256, bytesRead=3
//   [0xFE, ...]        -> 4-byte value, bytesRead=5
//   [0xFF, ...]        -> 8-byte value, bytesRead=9
func ReadVarInt(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"varint: offset %d beyond data length %d", offset, len(data))
	}

	firstByte := data[offset]

	switch {
	case firstByte < 0xFD:
		// Single byte value (0x00 - 0xFC)
		return uint64(firstByte), 1, nil

	case firstByte == 0xFD:
		// 0xFD prefix: next 2 bytes are little-endian uint16
		if offset+3 > len(data) {
			return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
				"varint: need 3 bytes at offset %d, have %d", offset, len(data)-offset)
		}
		value := binary.LittleEndian.Uint16(data[offset+1 : offset+3])
		return uint64(value), 3, nil

	case firstByte == 0xFE:
		// 0xFE prefix: next 4 bytes are little-endian uint32
		if offset+5 > len(data) {
			return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
				"varint: need 5 bytes at offset %d, have %d", offset, len(data)-offset)
		}
		value := binary.LittleEndian.Uint32(data[offset+1 : offset+5])
		return uint64(value), 5, nil

	default: // firstByte == 0xFF
		// 0xFF prefix: next 8 bytes are little-endian uint64
		if offset+9 > len(data) {
			return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
				"varint: need 9 bytes at offset %d, have %d", offset, len(data)-offset)
		}
		value := binary.LittleEndian.Uint64(data[offset+1 : offset+9])
		return uint64(value), 9, nil
	}
}

// VarIntSize returns the number of bytes needed to encode a value as CompactSize.
func VarIntSize(value uint64) int {
	switch {
	case value < 0xFD:
		return 1
	case value <= 0xFFFF:
		return 3
	case value <= 0xFFFFFFFF:
		return 5
	default:
		return 9
	}
}

// ReadBytes reads exactly n bytes from data starting at offset.
// Returns (bytes, bytesRead, error).
func ReadBytes(data []byte, offset int, n int) ([]byte, int, error) {
	if offset+n > len(data) {
		return nil, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"need %d bytes at offset %d, have %d", n, offset, len(data)-offset)
	}
	result := make([]byte, n)
	copy(result, data[offset:offset+n])
	return result, n, nil
}

// ReadUint32LE reads a 4-byte little-endian uint32.
func ReadUint32LE(data []byte, offset int) (uint32, int, error) {
	if offset+4 > len(data) {
		return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"need 4 bytes at offset %d, have %d", offset, len(data)-offset)
	}
	value := binary.LittleEndian.Uint32(data[offset : offset+4])
	return value, 4, nil
}

// ReadInt32LE reads a 4-byte little-endian int32.
func ReadInt32LE(data []byte, offset int) (int32, int, error) {
	if offset+4 > len(data) {
		return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"need 4 bytes at offset %d, have %d", offset, len(data)-offset)
	}
	value := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
	return value, 4, nil
}

// ReadUint64LE reads an 8-byte little-endian uint64.
func ReadUint64LE(data []byte, offset int) (uint64, int, error) {
	if offset+8 > len(data) {
		return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedTx,
			"need 8 bytes at offset %d, have %d", offset, len(data)-offset)
	}
	value := binary.LittleEndian.Uint64(data[offset : offset+8])
	return value, 8, nil
}

// =============================================================================
// SERIALIZATION VARINT (for undo data)
// =============================================================================
//
// Bitcoin Core's undo files use a different varint encoding than CompactSize.
// This "Serialization VarInt" uses base-128 MSB encoding:
//   - Each byte uses 7 bits for the number, MSB as continuation flag
//   - MSB=1 means more bytes follow
//   - Value is assembled from the 7-bit segments
//
// Example:
//   0x00       -> 0
//   0x7F       -> 127
//   0x80 0x00  -> 128      (0x80-0x80)*128 + 0x00 = 128
//   0x80 0x01  -> 129
//   0x81 0x00  -> 256      (0x81-0x80)*128 + 0x00+128 = 256
//
// Decoding: n = 0; while (byte & 0x80) { n = (n+1)*128 + (byte & 0x7F); } n += byte;

// ReadSerVarInt reads a Bitcoin Core serialization varint (base-128 MSB).
// Used in undo files for code, amount, and nSize fields.
//
// Bitcoin's serialization varint uses shift-accumulate with continuation bits:
//   - High bit (0x80) indicates more bytes follow
//   - After accumulating 7 bits from each continuation byte, add 1
//   - Final byte uses all 8 bits directly
func ReadSerVarInt(data []byte, offset int) (uint64, int, error) {
	var n uint64
	bytesRead := 0

	for {
		if offset+bytesRead >= len(data) {
			return 0, 0, models.NewAnalysisErrorf(models.ErrCodeTruncatedUndo,
				"servarint: unexpected end at offset %d+%d", offset, bytesRead)
		}

		b := data[offset+bytesRead]
		bytesRead++

		// Shift existing value left by 7 bits, OR in the lower 7 bits of current byte
		n = (n << 7) | uint64(b&0x7F)

		if b&0x80 != 0 {
			// High bit set means more bytes follow, add 1 to accumulated value
			n++
		} else {
			// High bit clear means this is the last byte
			break
		}

		// Safety: prevent infinite loops on malformed data
		if bytesRead > 10 {
			return 0, 0, models.NewAnalysisErrorf(models.ErrCodeInvalidUndoData,
				"servarint: too many bytes at offset %d", offset)
		}
	}

	return n, bytesRead, nil
}
