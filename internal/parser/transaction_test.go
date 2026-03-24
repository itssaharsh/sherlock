package parser

import (
	"testing"
)

// =============================================================================
// TEST TRANSACTIONS
// =============================================================================
//
// These are real Bitcoin transactions that demonstrate key parsing concepts.

// Legacy P2PKH transaction (non-SegWit)
// This is a simple 1-input, 2-output transaction.
//
// Byte layout:
// [01000000]                                                         - version (1)
// [01]                                                               - input count (1)
// [input 0: 32-byte txid + 4-byte vout + scriptsig + 4-byte seq]
// [02]                                                               - output count (2)
// [output 0: 8-byte value + scriptpubkey]
// [output 1: 8-byte value + scriptpubkey]
// [00000000]                                                         - locktime (0)
const legacyTxHex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"

// SegWit P2WPKH transaction (real transaction from mainnet)
// txid: d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c
//
// Byte layout:
// [01000000]                                                         - version (1)
// [00]                                                               - marker (SegWit indicator)
// [01]                                                               - flag (SegWit indicator)
// [01]                                                               - input count (1)
// [input 0: empty scriptsig for native SegWit]
// [02]                                                               - output count (2)
// [output 0 + output 1]
// [witness for input 0: 2 items (signature + pubkey)]
// [locktime]
const segwitTxHex = "01000000000101b8b9731dcf5f97ca0c79e57ae7c49710cc8a6af3be8b7b57e82cdd3b5c8afa6e0100000000ffffffff0200e1f5050000000017a914a860f76561c85551594c18eecceffaee8c4822d787f0c1a4350000000017a914d8b6fcc85a383261df05423ddf068a8987bf028787024730440220434caf5bb442cb6a251e8bce0ec493f9a1a9c4423bcfc029e542b0e8a89f1ef702206d0495dcf4c3469f13ebc4dd41e761a9e81e9db3d3e588d5ce1c532852d54d790121031fa4a28a3d66696aa9e02a553888b36d97adfc3b4824b6e8f3e72cae6c29b76500000000"

func TestParseLegacyTransaction(t *testing.T) {
	tx, err := ParseTransaction(legacyTxHex)
	if err != nil {
		t.Fatalf("Failed to parse legacy tx: %v", err)
	}

	// Verify basic properties
	if tx.IsSegwit {
		t.Error("Legacy tx should not be marked as SegWit")
	}

	if tx.Version != 1 {
		t.Errorf("Expected version 1, got %d", tx.Version)
	}

	if len(tx.Inputs) != 1 {
		t.Errorf("Expected 1 input, got %d", len(tx.Inputs))
	}

	if len(tx.Outputs) != 2 {
		t.Errorf("Expected 2 outputs, got %d", len(tx.Outputs))
	}

	if tx.Locktime != 0 {
		t.Errorf("Expected locktime 0, got %d", tx.Locktime)
	}

	// Verify weight calculation for legacy
	// For legacy: weight = size * 4, vbytes = size
	if tx.Weight() != tx.TotalSize*4 {
		t.Errorf("Legacy weight should be size*4, got %d (size=%d)", tx.Weight(), tx.TotalSize)
	}

	if tx.Vbytes() != tx.TotalSize {
		t.Errorf("Legacy vbytes should equal size, got %d (size=%d)", tx.Vbytes(), tx.TotalSize)
	}

	// Verify witness is empty for legacy
	for i, w := range tx.Witnesses {
		if len(w) != 0 {
			t.Errorf("Legacy input %d should have empty witness, got %d items", i, len(w))
		}
	}

	t.Logf("Legacy tx parsed: txid=%s, size=%d, weight=%d, vbytes=%d",
		tx.Txid(), tx.TotalSize, tx.Weight(), tx.Vbytes())
}

func TestParseSegwitTransaction(t *testing.T) {
	tx, err := ParseTransaction(segwitTxHex)
	if err != nil {
		t.Fatalf("Failed to parse SegWit tx: %v", err)
	}

	// Verify SegWit detection
	if !tx.IsSegwit {
		t.Error("SegWit tx should be marked as SegWit")
	}

	if tx.Marker != 0x00 || tx.Flag != 0x01 {
		t.Errorf("Expected marker=0x00, flag=0x01, got marker=0x%02x, flag=0x%02x",
			tx.Marker, tx.Flag)
	}

	if tx.Version != 1 {
		t.Errorf("Expected version 1, got %d", tx.Version)
	}

	// Verify witness data exists
	if len(tx.Witnesses) != len(tx.Inputs) {
		t.Errorf("Witness count should match input count")
	}

	for i, w := range tx.Witnesses {
		if len(w) == 0 {
			t.Errorf("SegWit input %d should have witness data", i)
		}
	}

	// Verify weight discount
	// Weight = (non-witness * 4) + (witness * 1)
	expectedWeight := (tx.NonWitnessSize * 4) + (tx.WitnessSize * 1)
	if tx.Weight() != expectedWeight {
		t.Errorf("Weight calculation mismatch: got %d, expected %d", tx.Weight(), expectedWeight)
	}

	// Verify vbytes is less than total size (SegWit discount)
	if tx.Vbytes() >= tx.TotalSize {
		t.Errorf("SegWit vbytes (%d) should be less than total size (%d)",
			tx.Vbytes(), tx.TotalSize)
	}

	// Verify wtxid is not nil for SegWit
	wtxid := tx.Wtxid()
	if wtxid == nil {
		t.Error("SegWit tx should have non-nil wtxid")
	}

	// Verify txid != wtxid for SegWit
	if wtxid != nil && tx.Txid() == *wtxid {
		t.Error("SegWit txid and wtxid should differ")
	}

	t.Logf("SegWit tx parsed: txid=%s, wtxid=%s", tx.Txid(), *wtxid)
	t.Logf("Size: total=%d, witness=%d, non-witness=%d", tx.TotalSize, tx.WitnessSize, tx.NonWitnessSize)
	t.Logf("Weight: %d WU, vbytes: %d", tx.Weight(), tx.Vbytes())
}

func TestWeightCalculation(t *testing.T) {
	// Test case: simulate a SegWit tx with known sizes
	//
	// Example:
	//   Total size: 222 bytes
	//   Witness: 107 bytes (marker + flag + witness stack)
	//   Non-witness: 115 bytes (version + inputs + outputs + locktime)
	//
	// Weight = (115 * 4) + (107 * 1) = 460 + 107 = 567 WU
	// Vbytes = ceil(567 / 4) = 142
	//
	// If this were legacy (no witness discount):
	// Weight = 222 * 4 = 888 WU
	// Savings = (888 - 567) / 888 = 36.15%

	tx := &RawTransaction{
		IsSegwit:       true,
		TotalSize:      222,
		WitnessSize:    107,
		NonWitnessSize: 115,
	}

	weight := tx.Weight()
	expectedWeight := (115 * 4) + (107 * 1) // = 567
	if weight != expectedWeight {
		t.Errorf("Weight: got %d, expected %d", weight, expectedWeight)
	}

	vbytes := tx.Vbytes()
	expectedVbytes := (567 + 3) / 4 // = 142
	if vbytes != expectedVbytes {
		t.Errorf("Vbytes: got %d, expected %d", vbytes, expectedVbytes)
	}

	legacyWeight := tx.WeightIfLegacy()
	expectedLegacy := 222 * 4 // = 888
	if legacyWeight != expectedLegacy {
		t.Errorf("Legacy weight: got %d, expected %d", legacyWeight, expectedLegacy)
	}

	// Calculate savings percentage
	savingsPct := float64(legacyWeight-weight) / float64(legacyWeight) * 100
	t.Logf("SegWit savings: %.2f%% (weight %d vs legacy %d)", savingsPct, weight, legacyWeight)
}

func TestVarIntParsing(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint64
		size     int
	}{
		{"single byte 0", []byte{0x00}, 0, 1},
		{"single byte 1", []byte{0x01}, 1, 1},
		{"single byte 252", []byte{0xFC}, 252, 1},
		{"two bytes 253", []byte{0xFD, 0xFD, 0x00}, 253, 3},
		{"two bytes 256", []byte{0xFD, 0x00, 0x01}, 256, 3},
		{"two bytes 65535", []byte{0xFD, 0xFF, 0xFF}, 65535, 3},
		{"four bytes", []byte{0xFE, 0x00, 0x00, 0x01, 0x00}, 65536, 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, n, err := ReadVarInt(tc.data, 0)
			if err != nil {
				t.Fatalf("ReadVarInt failed: %v", err)
			}
			if val != tc.expected {
				t.Errorf("Value: got %d, expected %d", val, tc.expected)
			}
			if n != tc.size {
				t.Errorf("Size: got %d, expected %d", n, tc.size)
			}
		})
	}
}

func TestInvalidTransactions(t *testing.T) {
	tests := []struct {
		name   string
		hex    string
		errMsg string
	}{
		{"too short", "0100", "too short"},
		{"invalid hex", "xyz123", "invalid hex"},
		{"truncated input", "01000000010000000000000000000000000000000000000000000000000000000000000000", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTransaction(tc.hex)
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}
