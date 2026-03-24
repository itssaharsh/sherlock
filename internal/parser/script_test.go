package parser

import (
	"encoding/hex"
	"testing"
)

func TestClassifyScript(t *testing.T) {
	tests := []struct {
		name       string
		scriptHex  string
		expectType ScriptType
	}{
		{
			name:       "P2PKH",
			scriptHex:  "76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac",
			expectType: ScriptTypeP2PKH,
		},
		{
			name:       "P2SH",
			scriptHex:  "a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "87",
			expectType: ScriptTypeP2SH,
		},
		{
			name:       "P2WPKH",
			scriptHex:  "0014" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba",
			expectType: ScriptTypeP2WPKH,
		},
		{
			name:       "P2WSH",
			scriptHex:  "0020" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba",
			expectType: ScriptTypeP2WSH,
		},
		{
			name:       "P2TR",
			scriptHex:  "5120" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba",
			expectType: ScriptTypeP2TR,
		},
		{
			name:       "P2PK compressed",
			scriptHex:  "21" + "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" + "ac",
			expectType: ScriptTypeP2PK,
		},
		{
			name:       "P2PK uncompressed",
			scriptHex:  "41" + "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8" + "ac",
			expectType: ScriptTypeP2PK,
		},
		{
			name:       "OP_RETURN simple",
			scriptHex:  "6a" + "0c" + "48656c6c6f20576f726c6421", // "Hello World!" 
			expectType: ScriptTypeOPReturn,
		},
		{
			name:       "OP_RETURN empty",
			scriptHex:  "6a",
			expectType: ScriptTypeOPReturn,
		},
		{
			name:       "Witness unknown v2",
			scriptHex:  "5214" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba",
			expectType: ScriptTypeWitnessUnkown,
		},
		{
			name:       "Bare multisig 2-of-3",
			scriptHex:  "52" + "21" + "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" + "21" + "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" + "21" + "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" + "53" + "ae",
			expectType: ScriptTypeP2MS,
		},
		{
			name:       "Empty script",
			scriptHex:  "",
			expectType: ScriptTypeNonStandard,
		},
		{
			name:       "Non-standard random",
			scriptHex:  "01020304",
			expectType: ScriptTypeNonStandard,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, err := hex.DecodeString(tt.scriptHex)
			if err != nil {
				t.Fatalf("invalid hex: %v", err)
			}
			got := ClassifyScript(script)
			if got != tt.expectType {
				t.Errorf("ClassifyScript() = %v, want %v", got, tt.expectType)
			}
		})
	}
}

func TestDisassembleScript(t *testing.T) {
	tests := []struct {
		name      string
		scriptHex string
		expectAsm string
	}{
		{
			name:      "P2PKH",
			scriptHex: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
			expectAsm: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 89abcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUALVERIFY OP_CHECKSIG",
		},
		{
			name:      "P2SH",
			scriptHex: "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87",
			expectAsm: "OP_HASH160 OP_PUSHBYTES_20 89abcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUAL",
		},
		{
			name:      "P2WPKH",
			scriptHex: "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba",
			expectAsm: "OP_0 OP_PUSHBYTES_20 89abcdefabbaabbaabbaabbaabbaabbaabbaabba",
		},
		{
			name:      "P2TR",
			scriptHex: "512089abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba",
			expectAsm: "OP_1 OP_PUSHBYTES_32 89abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba",
		},
		{
			name:      "OP_RETURN with text",
			scriptHex: "6a0c48656c6c6f20576f726c6421",
			expectAsm: "OP_RETURN OP_PUSHBYTES_12 48656c6c6f20576f726c6421",
		},
		{
			name:      "Empty script",
			scriptHex: "",
			expectAsm: "",
		},
		{
			name:      "Small integers",
			scriptHex: "00515293",
			expectAsm: "OP_0 OP_1 OP_2 OP_ADD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, _ := hex.DecodeString(tt.scriptHex)
			got, err := DisassembleScript(script)
			if err != nil {
				t.Fatalf("DisassembleScript() error = %v", err)
			}
			if got != tt.expectAsm {
				t.Errorf("DisassembleScript() =\n  %v\nwant\n  %v", got, tt.expectAsm)
			}
		})
	}
}

func TestExtractOPReturnData(t *testing.T) {
	tests := []struct {
		name         string
		scriptHex    string
		expectProto  OPReturnProtocol
		expectText   string
		expectPayHex string
	}{
		{
			name:         "Plain text",
			scriptHex:    "6a0c48656c6c6f20576f726c6421", // OP_RETURN OP_PUSHBYTES_12 "Hello World!"
			expectProto:  ProtocolText,
			expectText:   "Hello World!",
			expectPayHex: "48656c6c6f20576f726c6421",
		},
		{
			name:         "Omni Simple Send",
			// OP_RETURN OP_PUSHBYTES_20 "omni" + version(0) + type(0) + property_id + amount
			scriptHex:    "6a146f6d6e6900000000000000010000000005f5e100",
			expectProto:  ProtocolOmni,
			expectPayHex: "6f6d6e6900000000000000010000000005f5e100",
		},
		{
			name:         "OpenTimestamps",
			scriptHex:    "6a050109f91102", // minimal OTS marker
			expectProto:  ProtocolOpenTimestamps,
			expectPayHex: "0109f91102",
		},
		{
			name:         "Binary data (non-printable)",
			scriptHex:    "6a04deadbeef",
			expectProto:  ProtocolUnknown,
			expectText:   "",
			expectPayHex: "deadbeef",
		},
		{
			name:         "Empty OP_RETURN",
			scriptHex:    "6a",
			expectProto:  ProtocolUnknown,
			expectPayHex: "",
		},
		{
			name:         "Multiple pushes concatenated",
			scriptHex:    "6a0448454c4c044f212121", // HELL + O!!!
			expectProto:  ProtocolText,
			expectText:   "HELLO!!!",
			expectPayHex: "48454c4c4f212121",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, _ := hex.DecodeString(tt.scriptHex)
			data, err := ExtractOPReturnData(script)
			if err != nil {
				t.Fatalf("ExtractOPReturnData() error = %v", err)
			}
			if data.Protocol != tt.expectProto {
				t.Errorf("Protocol = %v, want %v", data.Protocol, tt.expectProto)
			}
			if data.Text != tt.expectText {
				t.Errorf("Text = %q, want %q", data.Text, tt.expectText)
			}
			if data.Payload != tt.expectPayHex {
				t.Errorf("Payload = %s, want %s", data.Payload, tt.expectPayHex)
			}
		})
	}
}

func TestExtractPubKeyHash(t *testing.T) {
	// P2PKH script
	p2pkh, _ := hex.DecodeString("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	hash, err := ExtractPubKeyHash(p2pkh)
	if err != nil {
		t.Fatalf("ExtractPubKeyHash(P2PKH) error = %v", err)
	}
	if hex.EncodeToString(hash) != "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" {
		t.Errorf("wrong hash extracted")
	}

	// P2WPKH script
	p2wpkh, _ := hex.DecodeString("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba")
	hash, err = ExtractPubKeyHash(p2wpkh)
	if err != nil {
		t.Fatalf("ExtractPubKeyHash(P2WPKH) error = %v", err)
	}
	if hex.EncodeToString(hash) != "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" {
		t.Errorf("wrong hash extracted")
	}
}

func TestExtractScriptHash(t *testing.T) {
	// P2SH script
	p2sh, _ := hex.DecodeString("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87")
	hash, err := ExtractScriptHash(p2sh)
	if err != nil {
		t.Fatalf("ExtractScriptHash(P2SH) error = %v", err)
	}
	if hex.EncodeToString(hash) != "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" {
		t.Errorf("wrong hash extracted")
	}

	// P2WSH script
	p2wsh, _ := hex.DecodeString("002089abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba")
	hash, err = ExtractScriptHash(p2wsh)
	if err != nil {
		t.Fatalf("ExtractScriptHash(P2WSH) error = %v", err)
	}
	if hex.EncodeToString(hash) != "89abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba" {
		t.Errorf("wrong hash extracted")
	}
}

func TestExtractTaprootKey(t *testing.T) {
	p2tr, _ := hex.DecodeString("512089abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba")
	key, err := ExtractTaprootKey(p2tr)
	if err != nil {
		t.Fatalf("ExtractTaprootKey() error = %v", err)
	}
	if hex.EncodeToString(key) != "89abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba" {
		t.Errorf("wrong key extracted")
	}
}

func TestDisassemblePushData(t *testing.T) {
	// Test PUSHDATA1 (length 76-255)
	// Build: OP_RETURN + PUSHDATA1 + len(80) + 80 bytes of 'aa'
	scriptHex := "6a4c50" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	script, _ := hex.DecodeString(scriptHex)
	
	asm, err := DisassembleScript(script)
	if err != nil {
		t.Fatalf("DisassembleScript() error = %v", err)
	}
	if !contains(asm, "OP_PUSHDATA1") {
		t.Errorf("Expected OP_PUSHDATA1 in asm: %s", asm)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
