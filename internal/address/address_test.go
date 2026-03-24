package address

import (
	"encoding/hex"
	"testing"
)

func TestEncodeP2PKH(t *testing.T) {
	// Test vector: known pubkey hash -> address
	// This is from Bitcoin wiki / BIP examples
	tests := []struct {
		name      string
		hashHex   string
		expected  string
	}{
		{
			name:     "Standard P2PKH",
			hashHex:  "751e76e8199196d454941c45d1b3a323f1433bd6",
			expected: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
		},
		{
			name:     "All zeros",
			hashHex:  "0000000000000000000000000000000000000000",
			expected: "1111111111111111111114oLvT2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hashHex)
			addr, err := EncodeP2PKH(hash)
			if err != nil {
				t.Fatalf("EncodeP2PKH() error = %v", err)
			}
			if addr != tt.expected {
				t.Errorf("EncodeP2PKH() = %q, want %q", addr, tt.expected)
			}
		})
	}
}

func TestEncodeP2SH(t *testing.T) {
	tests := []struct {
		name     string
		hashHex  string
		expected string
	}{
		{
			// Known P2SH address test vector
			name:     "Standard P2SH",
			hashHex:  "f815b036d9bbbce5e9f2a00abd1bf3dc91e95510",
			expected: "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hashHex)
			addr, err := EncodeP2SH(hash)
			if err != nil {
				t.Fatalf("EncodeP2SH() error = %v", err)
			}
			if addr != tt.expected {
				t.Errorf("EncodeP2SH() = %q, want %q", addr, tt.expected)
			}
		})
	}
}

func TestEncodeP2WPKH(t *testing.T) {
	// BIP173 test vectors
	tests := []struct {
		name     string
		hashHex  string
		expected string
	}{
		{
			name:     "BIP173 vector 1",
			hashHex:  "751e76e8199196d454941c45d1b3a323f1433bd6",
			expected: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hashHex)
			addr, err := EncodeP2WPKH(hash)
			if err != nil {
				t.Fatalf("EncodeP2WPKH() error = %v", err)
			}
			if addr != tt.expected {
				t.Errorf("EncodeP2WPKH() = %q, want %q", addr, tt.expected)
			}
		})
	}
}

func TestEncodeP2WSH(t *testing.T) {
	// BIP173 test vectors
	tests := []struct {
		name     string
		hashHex  string
		expected string
	}{
		{
			name:     "BIP173 vector",
			hashHex:  "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
			expected: "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hashHex)
			addr, err := EncodeP2WSH(hash)
			if err != nil {
				t.Fatalf("EncodeP2WSH() error = %v", err)
			}
			if addr != tt.expected {
				t.Errorf("EncodeP2WSH() = %q, want %q", addr, tt.expected)
			}
		})
	}
}

func TestEncodeP2TR(t *testing.T) {
	// BIP350 test vectors for Taproot (Bech32m)
	tests := []struct {
		name     string
		keyHex   string
		expected string
	}{
		{
			name:     "BIP350 vector",
			keyHex:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			expected: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.keyHex)
			addr, err := EncodeP2TR(key)
			if err != nil {
				t.Fatalf("EncodeP2TR() error = %v", err)
			}
			if addr != tt.expected {
				t.Errorf("EncodeP2TR() = %q, want %q", addr, tt.expected)
			}
		})
	}
}

func TestInvalidInput(t *testing.T) {
	// Test with wrong-length input
	shortHash := make([]byte, 19)
	if _, err := EncodeP2PKH(shortHash); err == nil {
		t.Error("EncodeP2PKH should fail with 19-byte input")
	}
	if _, err := EncodeP2WPKH(shortHash); err == nil {
		t.Error("EncodeP2WPKH should fail with 19-byte input")
	}

	shortKey := make([]byte, 31)
	if _, err := EncodeP2TR(shortKey); err == nil {
		t.Error("EncodeP2TR should fail with 31-byte input")
	}
}
