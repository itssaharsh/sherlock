package parser

import (
	"encoding/hex"
	"testing"
)

func TestBlockHeaderParsing(t *testing.T) {
	// Genesis block header (block 0)
	// This is the famous genesis block with the Times headline
	genesisHeaderHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

	headerBytes, err := hex.DecodeString(genesisHeaderHex)
	if err != nil {
		t.Fatalf("Failed to decode header hex: %v", err)
	}

	header, err := ParseBlockHeader(headerBytes)
	if err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}

	// Verify version
	if header.Version != 1 {
		t.Errorf("Expected version 1, got %d", header.Version)
	}

	// Verify previous block hash (all zeros for genesis)
	for _, b := range header.PrevBlockHash {
		if b != 0 {
			t.Error("Genesis prev block hash should be all zeros")
			break
		}
	}

	// Verify timestamp (2009-01-03 18:15:05 UTC)
	expectedTimestamp := uint32(1231006505)
	if header.Timestamp != expectedTimestamp {
		t.Errorf("Expected timestamp %d, got %d", expectedTimestamp, header.Timestamp)
	}

	// Verify bits (difficulty target)
	expectedBits := uint32(0x1d00ffff)
	if header.Bits != expectedBits {
		t.Errorf("Expected bits 0x%08x, got 0x%08x", expectedBits, header.Bits)
	}

	// Verify nonce
	expectedNonce := uint32(2083236893)
	if header.Nonce != expectedNonce {
		t.Errorf("Expected nonce %d, got %d", expectedNonce, header.Nonce)
	}

	// Verify block hash
	// Genesis block hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
	expectedHash := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	actualHash := header.BlockHash()
	if actualHash != expectedHash {
		t.Errorf("Block hash mismatch:\nexpected: %s\ngot:      %s", expectedHash, actualHash)
	}

	t.Logf("Genesis block parsed successfully:")
	t.Logf("  Hash: %s", actualHash)
	t.Logf("  Merkle root: %s", header.MerkleRootHex())
	t.Logf("  Timestamp: %d", header.Timestamp)
}

func TestMerkleRootCalculation(t *testing.T) {
	// Test with known merkle root calculation
	// Block 100000 has 4 transactions
	// We'll use a simple 2-tx example first

	// For a single transaction, merkle root = txid
	singleTxid := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
	root, err := ComputeMerkleRootFromTxids([]string{singleTxid})
	if err != nil {
		t.Fatalf("Failed to compute merkle root: %v", err)
	}

	// For single tx, merkle root equals the txid (in internal byte order)
	// Convert txid to internal order and compare
	expectedRoot := singleTxid
	actualRoot := reverseHex(root[:])
	if actualRoot != expectedRoot {
		t.Errorf("Single tx merkle root mismatch:\nexpected: %s\ngot:      %s", expectedRoot, actualRoot)
	}

	// Test with 2 transactions
	// merkle_root = SHA256(SHA256(txid1 || txid2))
	tx1 := "0000000000000000000000000000000000000000000000000000000000000001"
	tx2 := "0000000000000000000000000000000000000000000000000000000000000002"

	root2, err := ComputeMerkleRootFromTxids([]string{tx1, tx2})
	if err != nil {
		t.Fatalf("Failed to compute 2-tx merkle root: %v", err)
	}

	t.Logf("2-tx merkle root: %s", reverseHex(root2[:]))

	// Test with 3 transactions (odd number - last is duplicated)
	tx3 := "0000000000000000000000000000000000000000000000000000000000000003"
	root3, err := ComputeMerkleRootFromTxids([]string{tx1, tx2, tx3})
	if err != nil {
		t.Fatalf("Failed to compute 3-tx merkle root: %v", err)
	}

	t.Logf("3-tx merkle root: %s", reverseHex(root3[:]))
}

func TestAmountDecompression(t *testing.T) {
	// Test cases for Bitcoin Core's amount compression
	// Based on Bitcoin Core's compressor.h DecompressAmount
	//
	// Compression scheme:
	// - if n == 0: return 0
	// - n--; e = n % 10; n /= 10
	// - if e < 9: d = (n % 9) + 1; n /= 9; return (n * 10 + d) * 10^e
	// - else: return (n + 1) * 10^9

	tests := []struct {
		compressed   uint64
		decompressed uint64
	}{
		{0, 0},             // Special case
		{1, 1},             // 0*10+1 * 10^0 = 1
		{2, 10},            // 0*10+1 * 10^1 = 10
		{3, 100},           // 0*10+1 * 10^2 = 100
		{4, 1000},          // 0*10+1 * 10^3 = 1000
		{5, 10000},         // 10^4
		{6, 100000},        // 10^5
		{7, 1000000},       // 10^6
		{8, 10000000},      // 10^7
		{9, 100000000},     // 10^8 = 1 BTC
		{10, 1000000000},   // e=9: (0+1) * 10^9 = 10^9 = 10 BTC
	}

	for _, tc := range tests {
		result := decompressAmount(tc.compressed)
		if result != tc.decompressed {
			t.Errorf("decompressAmount(%d) = %d, expected %d",
				tc.compressed, result, tc.decompressed)
		}
	}
}

func TestCompressedScriptP2PKH(t *testing.T) {
	// nSize = 0: P2PKH
	// Input: 20-byte pubkey hash
	// Output: 25-byte P2PKH script

	pubkeyHash, _ := hex.DecodeString("89abcdef0123456789abcdef0123456789abcdef")

	// Build test data: [nSize=0] [20-byte hash]
	testData := append([]byte{0x00}, pubkeyHash...)

	script, n, err := readCompressedScript(testData, 0)
	if err != nil {
		t.Fatalf("Failed to decompress P2PKH: %v", err)
	}

	// Verify length
	if len(script) != 25 {
		t.Errorf("P2PKH script should be 25 bytes, got %d", len(script))
	}

	// Verify structure
	if script[0] != 0x76 { // OP_DUP
		t.Error("P2PKH should start with OP_DUP")
	}
	if script[1] != 0xa9 { // OP_HASH160
		t.Error("P2PKH byte 1 should be OP_HASH160")
	}
	if script[2] != 0x14 { // Push 20 bytes
		t.Error("P2PKH byte 2 should be 0x14 (push 20)")
	}
	if script[23] != 0x88 { // OP_EQUALVERIFY
		t.Error("P2PKH byte 23 should be OP_EQUALVERIFY")
	}
	if script[24] != 0xac { // OP_CHECKSIG
		t.Error("P2PKH byte 24 should be OP_CHECKSIG")
	}

	// Verify bytes read
	if n != 21 { // 1 byte nSize + 20 bytes hash
		t.Errorf("Expected 21 bytes read, got %d", n)
	}

	t.Logf("Decompressed P2PKH script: %s", hex.EncodeToString(script))
}

func TestCompressedScriptP2SH(t *testing.T) {
	// nSize = 1: P2SH
	scriptHash, _ := hex.DecodeString("0123456789abcdef0123456789abcdef01234567")

	testData := append([]byte{0x01}, scriptHash...)

	script, n, err := readCompressedScript(testData, 0)
	if err != nil {
		t.Fatalf("Failed to decompress P2SH: %v", err)
	}

	if len(script) != 23 {
		t.Errorf("P2SH script should be 23 bytes, got %d", len(script))
	}

	if script[0] != 0xa9 { // OP_HASH160
		t.Error("P2SH should start with OP_HASH160")
	}
	if script[22] != 0x87 { // OP_EQUAL
		t.Error("P2SH should end with OP_EQUAL")
	}

	if n != 21 {
		t.Errorf("Expected 21 bytes read, got %d", n)
	}

	t.Logf("Decompressed P2SH script: %s", hex.EncodeToString(script))
}

func TestCompressedScriptP2PK(t *testing.T) {
	// nSize = 2: P2PK compressed, even Y
	// nSize = 3: P2PK compressed, odd Y
	xCoord, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	// Test nSize = 2 (even Y)
	testData := append([]byte{0x02}, xCoord...)
	script, n, err := readCompressedScript(testData, 0)
	if err != nil {
		t.Fatalf("Failed to decompress P2PK (even): %v", err)
	}

	if len(script) != 35 {
		t.Errorf("P2PK script should be 35 bytes, got %d", len(script))
	}
	if script[0] != 0x21 { // Push 33 bytes
		t.Error("P2PK should start with 0x21")
	}
	if script[1] != 0x02 { // Even Y prefix
		t.Error("Even Y P2PK should have 0x02 prefix")
	}
	if script[34] != 0xac { // OP_CHECKSIG
		t.Error("P2PK should end with OP_CHECKSIG")
	}

	if n != 33 { // 1 byte nSize + 32 bytes X
		t.Errorf("Expected 33 bytes read, got %d", n)
	}

	// Test nSize = 3 (odd Y)
	testData = append([]byte{0x03}, xCoord...)
	script, _, err = readCompressedScript(testData, 0)
	if err != nil {
		t.Fatalf("Failed to decompress P2PK (odd): %v", err)
	}

	if script[1] != 0x03 { // Odd Y prefix
		t.Error("Odd Y P2PK should have 0x03 prefix")
	}

	t.Logf("Decompressed P2PK script: %s", hex.EncodeToString(script))
}

func TestCompressedScriptRaw(t *testing.T) {
	// nSize >= 6: Raw script, length = nSize - 6

	// Test raw script of length 10 (nSize = 16)
	rawScript, _ := hex.DecodeString("00112233445566778899")

	// nSize = 16 means script length = 16 - 6 = 10
	testData := append([]byte{0x10}, rawScript...) // 0x10 = 16

	script, n, err := readCompressedScript(testData, 0)
	if err != nil {
		t.Fatalf("Failed to decompress raw script: %v", err)
	}

	if len(script) != 10 {
		t.Errorf("Raw script should be 10 bytes, got %d", len(script))
	}

	expectedHex := "00112233445566778899"
	actualHex := hex.EncodeToString(script)
	if actualHex != expectedHex {
		t.Errorf("Script mismatch:\nexpected: %s\ngot:      %s", expectedHex, actualHex)
	}

	if n != 11 { // 1 byte nSize + 10 bytes script
		t.Errorf("Expected 11 bytes read, got %d", n)
	}

	t.Logf("Decompressed raw script: %s", actualHex)
}
