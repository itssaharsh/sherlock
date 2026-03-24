package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ScriptType represents the type of a Bitcoin script.
type ScriptType string

const (
	ScriptTypeP2PKH         ScriptType = "P2PKH"          // Pay to Public Key Hash
	ScriptTypeP2SH          ScriptType = "P2SH"           // Pay to Script Hash
	ScriptTypeP2WPKH        ScriptType = "P2WPKH"         // Pay to Witness Public Key Hash
	ScriptTypeP2WSH         ScriptType = "P2WSH"          // Pay to Witness Script Hash
	ScriptTypeP2TR          ScriptType = "P2TR"           // Pay to Taproot
	ScriptTypeP2PK          ScriptType = "P2PK"           // Pay to Public Key (legacy)
	ScriptTypeP2MS          ScriptType = "P2MS"           // Pay to Multisig (bare)
	ScriptTypeOPReturn      ScriptType = "OP_RETURN"      // Data output (unspendable)
	ScriptTypeWitnessUnkown ScriptType = "WITNESS_UNKNOWN" // Unknown witness version
	ScriptTypeNonStandard   ScriptType = "NON_STANDARD"   // Non-standard script
)

// OPReturnProtocol represents a known OP_RETURN protocol.
type OPReturnProtocol string

const (
	ProtocolUnknown        OPReturnProtocol = "unknown"
	ProtocolOmni           OPReturnProtocol = "omni"
	ProtocolOpenTimestamps OPReturnProtocol = "opentimestamps"
	ProtocolText           OPReturnProtocol = "text" // Printable ASCII text
)

// OPReturnData holds parsed OP_RETURN payload information.
type OPReturnData struct {
	Protocol OPReturnProtocol `json:"protocol"`
	Payload  string           `json:"payload_hex"`
	Text     string           `json:"text,omitempty"`     // Decoded text if printable
	Message  string           `json:"message,omitempty"`  // Human-readable protocol info
}

// ClassifyScript determines the type of a script from its bytes.
func ClassifyScript(script []byte) ScriptType {
	if len(script) == 0 {
		return ScriptTypeNonStandard
	}

	// P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	// 76 a9 14 <20 bytes> 88 ac (25 bytes total)
	if len(script) == 25 &&
		script[0] == byte(OP_DUP) &&
		script[1] == byte(OP_HASH160) &&
		script[2] == 0x14 && // push 20 bytes
		script[23] == byte(OP_EQUALVERIFY) &&
		script[24] == byte(OP_CHECKSIG) {
		return ScriptTypeP2PKH
	}

	// P2SH: OP_HASH160 <20 bytes> OP_EQUAL
	// a9 14 <20 bytes> 87 (23 bytes total)
	if len(script) == 23 &&
		script[0] == byte(OP_HASH160) &&
		script[1] == 0x14 && // push 20 bytes
		script[22] == byte(OP_EQUAL) {
		return ScriptTypeP2SH
	}

	// P2WPKH: OP_0 <20 bytes>
	// 00 14 <20 bytes> (22 bytes total)
	if len(script) == 22 &&
		script[0] == byte(OP_0) &&
		script[1] == 0x14 { // push 20 bytes
		return ScriptTypeP2WPKH
	}

	// P2WSH: OP_0 <32 bytes>
	// 00 20 <32 bytes> (34 bytes total)
	if len(script) == 34 &&
		script[0] == byte(OP_0) &&
		script[1] == 0x20 { // push 32 bytes
		return ScriptTypeP2WSH
	}

	// P2TR: OP_1 <32 bytes>
	// 51 20 <32 bytes> (34 bytes total)
	if len(script) == 34 &&
		script[0] == byte(OP_1) &&
		script[1] == 0x20 { // push 32 bytes
		return ScriptTypeP2TR
	}

	// Witness unknown: OP_n (n=2-16) <2-40 bytes>
	if len(script) >= 4 && len(script) <= 42 {
		version := script[0]
		if version >= byte(OP_2) && version <= byte(OP_16) {
			pushLen := int(script[1])
			if pushLen >= 2 && pushLen <= 40 && len(script) == 2+pushLen {
				return ScriptTypeWitnessUnkown
			}
		}
	}

	// P2PK: <33 or 65 bytes pubkey> OP_CHECKSIG
	// Compressed: 21 <33 bytes> ac (35 bytes)
	// Uncompressed: 41 <65 bytes> ac (67 bytes)
	if (len(script) == 35 && script[0] == 0x21 && script[34] == byte(OP_CHECKSIG)) ||
		(len(script) == 67 && script[0] == 0x41 && script[66] == byte(OP_CHECKSIG)) {
		return ScriptTypeP2PK
	}

	// OP_RETURN: OP_RETURN [data...]
	if len(script) >= 1 && script[0] == byte(OP_RETURN) {
		return ScriptTypeOPReturn
	}

	// Bare multisig: OP_m <pubkeys...> OP_n OP_CHECKMULTISIG
	if len(script) >= 4 {
		first := script[0]
		last := script[len(script)-1]
		if first >= byte(OP_1) && first <= byte(OP_16) &&
			last == byte(OP_CHECKMULTISIG) {
			// Check for OP_n before CHECKMULTISIG
			secondLast := script[len(script)-2]
			if secondLast >= byte(OP_1) && secondLast <= byte(OP_16) {
				return ScriptTypeP2MS
			}
		}
	}

	return ScriptTypeNonStandard
}

// ClassifyScriptHex classifies a script from its hex string.
func ClassifyScriptHex(scriptHex string) (ScriptType, error) {
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		return ScriptTypeNonStandard, fmt.Errorf("invalid hex: %w", err)
	}
	return ClassifyScript(script), nil
}

// DisassembleScript converts script bytes to human-readable assembly format.
func DisassembleScript(script []byte) (string, error) {
	if len(script) == 0 {
		return "", nil
	}

	var parts []string
	i := 0

	for i < len(script) {
		op := script[i]
		i++

		// Direct push: 0x01-0x4b pushes that many bytes
		if op >= 0x01 && op <= 0x4b {
			pushLen := int(op)
			if i+pushLen > len(script) {
				return "", fmt.Errorf("script truncated: expected %d bytes at offset %d", pushLen, i-1)
			}
			data := script[i : i+pushLen]
			parts = append(parts, fmt.Sprintf("OP_PUSHBYTES_%d %s", pushLen, hex.EncodeToString(data)))
			i += pushLen
			continue
		}

		// OP_PUSHDATA1: next byte is length, then data
		if op == byte(OP_PUSHDATA1) {
			if i >= len(script) {
				return "", fmt.Errorf("OP_PUSHDATA1 truncated at offset %d", i-1)
			}
			pushLen := int(script[i])
			i++
			if i+pushLen > len(script) {
				return "", fmt.Errorf("OP_PUSHDATA1 data truncated: expected %d bytes", pushLen)
			}
			data := script[i : i+pushLen]
			parts = append(parts, fmt.Sprintf("OP_PUSHDATA1 %s", hex.EncodeToString(data)))
			i += pushLen
			continue
		}

		// OP_PUSHDATA2: next 2 bytes (LE) is length, then data
		if op == byte(OP_PUSHDATA2) {
			if i+2 > len(script) {
				return "", fmt.Errorf("OP_PUSHDATA2 truncated at offset %d", i-1)
			}
			pushLen := int(binary.LittleEndian.Uint16(script[i : i+2]))
			i += 2
			if i+pushLen > len(script) {
				return "", fmt.Errorf("OP_PUSHDATA2 data truncated: expected %d bytes", pushLen)
			}
			data := script[i : i+pushLen]
			parts = append(parts, fmt.Sprintf("OP_PUSHDATA2 %s", hex.EncodeToString(data)))
			i += pushLen
			continue
		}

		// OP_PUSHDATA4: next 4 bytes (LE) is length, then data
		if op == byte(OP_PUSHDATA4) {
			if i+4 > len(script) {
				return "", fmt.Errorf("OP_PUSHDATA4 truncated at offset %d", i-1)
			}
			pushLen := int(binary.LittleEndian.Uint32(script[i : i+4]))
			i += 4
			if i+pushLen > len(script) {
				return "", fmt.Errorf("OP_PUSHDATA4 data truncated: expected %d bytes", pushLen)
			}
			data := script[i : i+pushLen]
			parts = append(parts, fmt.Sprintf("OP_PUSHDATA4 %s", hex.EncodeToString(data)))
			i += pushLen
			continue
		}

		// Regular opcode
		parts = append(parts, OpcodeName(Opcode(op)))
	}

	return strings.Join(parts, " "), nil
}

// DisassembleScriptHex disassembles a script from its hex string.
func DisassembleScriptHex(scriptHex string) (string, error) {
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex: %w", err)
	}
	return DisassembleScript(script)
}

// ExtractOPReturnData extracts and analyzes OP_RETURN payload.
func ExtractOPReturnData(script []byte) (*OPReturnData, error) {
	if len(script) == 0 || script[0] != byte(OP_RETURN) {
		return nil, fmt.Errorf("not an OP_RETURN script")
	}

	// Extract payload (concatenate all pushed data)
	payload := extractPayloadData(script[1:])

	result := &OPReturnData{
		Protocol: ProtocolUnknown,
		Payload:  hex.EncodeToString(payload),
	}

	// Check for known protocols
	result.Protocol, result.Message = detectProtocol(payload)

	// Check if printable ASCII text
	if isPrintableASCII(payload) {
		result.Text = string(payload)
		if result.Protocol == ProtocolUnknown {
			result.Protocol = ProtocolText
		}
	}

	return result, nil
}

// ExtractOPReturnDataHex extracts OP_RETURN data from hex script.
func ExtractOPReturnDataHex(scriptHex string) (*OPReturnData, error) {
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return ExtractOPReturnData(script)
}

// extractPayloadData extracts all pushed data from script bytes (after OP_RETURN).
func extractPayloadData(data []byte) []byte {
	var payload []byte
	i := 0

	for i < len(data) {
		op := data[i]
		i++

		// Direct push: 0x01-0x4b
		if op >= 0x01 && op <= 0x4b {
			pushLen := int(op)
			if i+pushLen > len(data) {
				break
			}
			payload = append(payload, data[i:i+pushLen]...)
			i += pushLen
			continue
		}

		// OP_PUSHDATA1
		if op == byte(OP_PUSHDATA1) {
			if i >= len(data) {
				break
			}
			pushLen := int(data[i])
			i++
			if i+pushLen > len(data) {
				break
			}
			payload = append(payload, data[i:i+pushLen]...)
			i += pushLen
			continue
		}

		// OP_PUSHDATA2
		if op == byte(OP_PUSHDATA2) {
			if i+2 > len(data) {
				break
			}
			pushLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
			i += 2
			if i+pushLen > len(data) {
				break
			}
			payload = append(payload, data[i:i+pushLen]...)
			i += pushLen
			continue
		}

		// OP_PUSHDATA4
		if op == byte(OP_PUSHDATA4) {
			if i+4 > len(data) {
				break
			}
			pushLen := int(binary.LittleEndian.Uint32(data[i : i+4]))
			i += 4
			if i+pushLen > len(data) {
				break
			}
			payload = append(payload, data[i:i+pushLen]...)
			i += pushLen
			continue
		}

		// OP_0 pushes empty data
		if op == byte(OP_0) {
			continue
		}

		// OP_1NEGATE to OP_16 push small integers (not typically data)
		// Stop on any other opcode
		break
	}

	return payload
}

// Omni protocol magic bytes: "omni" in hex
var omniMagic = []byte{0x6f, 0x6d, 0x6e, 0x69}

// OpenTimestamps magic: 0x0109f91102
var otsMagic = []byte{0x01, 0x09, 0xf9, 0x11, 0x02}

// detectProtocol identifies known OP_RETURN protocols.
func detectProtocol(payload []byte) (OPReturnProtocol, string) {
	if len(payload) == 0 {
		return ProtocolUnknown, ""
	}

	// Omni Layer (formerly Mastercoin): starts with "omni" (0x6f6d6e69)
	if len(payload) >= 4 && bytes.HasPrefix(payload, omniMagic) {
		return ProtocolOmni, decodeOmniMessage(payload)
	}

	// OpenTimestamps: starts with 0x0109f91102
	if len(payload) >= 5 && bytes.HasPrefix(payload, otsMagic) {
		return ProtocolOpenTimestamps, "OpenTimestamps calendar commitment"
	}

	return ProtocolUnknown, ""
}

// decodeOmniMessage attempts to decode Omni Layer message type.
func decodeOmniMessage(payload []byte) string {
	if len(payload) < 8 {
		return "Omni Layer transaction (incomplete)"
	}

	// Omni format after magic: 2-byte version, 2-byte message type
	// version := binary.BigEndian.Uint16(payload[4:6])
	msgType := binary.BigEndian.Uint16(payload[6:8])

	switch msgType {
	case 0:
		return "Omni Simple Send"
	case 1:
		return "Omni Participate in Crowdsale"
	case 2:
		return "Omni Trade"
	case 3:
		return "Omni Purchase DEx"
	case 4:
		return "Omni DEx Sell Offer"
	case 20:
		return "Omni DEx Accept"
	case 22:
		return "Omni Cancel DEx"
	case 25:
		return "Omni MetaDEx"
	case 26:
		return "Omni MetaDEx Cancel Price"
	case 27:
		return "Omni MetaDEx Cancel Pair"
	case 28:
		return "Omni MetaDEx Cancel All"
	case 50:
		return "Omni Create Property Fixed"
	case 51:
		return "Omni Create Property Variable"
	case 53:
		return "Omni Close Crowdsale"
	case 54:
		return "Omni Create Property Manual"
	case 55:
		return "Omni Grant Tokens"
	case 56:
		return "Omni Revoke Tokens"
	case 70:
		return "Omni Change Issuer"
	case 71:
		return "Omni Enable Freezing"
	case 72:
		return "Omni Disable Freezing"
	case 185:
		return "Omni Freeze Tokens"
	case 186:
		return "Omni Unfreeze Tokens"
	default:
		return fmt.Sprintf("Omni Layer message type %d", msgType)
	}
}

// isPrintableASCII checks if all bytes are printable ASCII (0x20-0x7E) or common whitespace.
func isPrintableASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		// Allow printable ASCII (space through tilde) and common whitespace
		if !((b >= 0x20 && b <= 0x7e) || b == 0x09 || b == 0x0a || b == 0x0d) {
			return false
		}
	}
	return true
}

// ExtractPubKeyHash extracts the hash from P2PKH or P2WPKH scripts.
func ExtractPubKeyHash(script []byte) ([]byte, error) {
	scriptType := ClassifyScript(script)
	switch scriptType {
	case ScriptTypeP2PKH:
		// 76 a9 14 <20 bytes> 88 ac
		return script[3:23], nil
	case ScriptTypeP2WPKH:
		// 00 14 <20 bytes>
		return script[2:22], nil
	default:
		return nil, fmt.Errorf("script is not P2PKH or P2WPKH")
	}
}

// ExtractScriptHash extracts the hash from P2SH or P2WSH scripts.
func ExtractScriptHash(script []byte) ([]byte, error) {
	scriptType := ClassifyScript(script)
	switch scriptType {
	case ScriptTypeP2SH:
		// a9 14 <20 bytes> 87
		return script[2:22], nil
	case ScriptTypeP2WSH:
		// 00 20 <32 bytes>
		return script[2:34], nil
	default:
		return nil, fmt.Errorf("script is not P2SH or P2WSH")
	}
}

// ExtractTaprootKey extracts the 32-byte x-only pubkey from P2TR scripts.
func ExtractTaprootKey(script []byte) ([]byte, error) {
	if ClassifyScript(script) != ScriptTypeP2TR {
		return nil, fmt.Errorf("script is not P2TR")
	}
	// 51 20 <32 bytes>
	return script[2:34], nil
}

// ExtractPubKey extracts the public key from P2PK scripts.
func ExtractPubKey(script []byte) ([]byte, error) {
	if ClassifyScript(script) != ScriptTypeP2PK {
		return nil, fmt.Errorf("script is not P2PK")
	}
	// 21 <33 bytes> ac or 41 <65 bytes> ac
	if len(script) == 35 {
		return script[1:34], nil
	}
	if len(script) == 67 {
		return script[1:66], nil
	}
	return nil, fmt.Errorf("invalid P2PK script length")
}

// InputScriptType represents the type of input spend.
type InputScriptType string

const (
	InputTypeP2PKH       InputScriptType = "p2pkh"
	InputTypeP2SH_P2WPKH InputScriptType = "p2sh-p2wpkh"
	InputTypeP2SH_P2WSH  InputScriptType = "p2sh-p2wsh"
	InputTypeP2WPKH      InputScriptType = "p2wpkh"
	InputTypeP2WSH       InputScriptType = "p2wsh"
	InputTypeP2TR_Key    InputScriptType = "p2tr_keypath"
	InputTypeP2TR_Script InputScriptType = "p2tr_scriptpath"
	InputTypeUnknown     InputScriptType = "unknown"
)

// ClassifyInput classifies an input based on prevout scriptPubKey, scriptSig, and witness.
func ClassifyInput(prevoutScript []byte, scriptSig []byte, witness [][]byte) InputScriptType {
	prevoutType := ClassifyScript(prevoutScript)

	switch prevoutType {
	case ScriptTypeP2PKH:
		// Native P2PKH spend: scriptSig has <sig> <pubkey>
		return InputTypeP2PKH

	case ScriptTypeP2WPKH:
		// Native SegWit P2WPKH: empty scriptSig, 2-item witness
		if len(scriptSig) == 0 && len(witness) == 2 {
			return InputTypeP2WPKH
		}
		return InputTypeUnknown

	case ScriptTypeP2WSH:
		// Native SegWit P2WSH: empty scriptSig, witness ends with script
		if len(scriptSig) == 0 && len(witness) >= 1 {
			return InputTypeP2WSH
		}
		return InputTypeUnknown

	case ScriptTypeP2TR:
		// Taproot: empty scriptSig
		if len(scriptSig) == 0 {
			return classifyTaprootSpend(witness)
		}
		return InputTypeUnknown

	case ScriptTypeP2SH:
		// Could be P2SH-P2WPKH or P2SH-P2WSH (nested SegWit)
		return classifyP2SHSpend(scriptSig, witness)

	default:
		return InputTypeUnknown
	}
}

// classifyTaprootSpend classifies a Taproot spend as keypath or scriptpath.
func classifyTaprootSpend(witness [][]byte) InputScriptType {
	if len(witness) == 0 {
		return InputTypeUnknown
	}

	// Check for annex (last item starts with 0x50)
	witnessLen := len(witness)
	hasAnnex := false
	if witnessLen >= 2 && len(witness[witnessLen-1]) > 0 && witness[witnessLen-1][0] == 0x50 {
		hasAnnex = true
		witnessLen--
	}

	// Keypath: single item (64 or 65 bytes for Schnorr signature)
	if witnessLen == 1 {
		sigLen := len(witness[0])
		if sigLen == 64 || sigLen == 65 {
			return InputTypeP2TR_Key
		}
	}

	// Scriptpath: at least 2 items (script + control block)
	// Control block starts with 0xc0 or 0xc1 (leaf version + parity)
	if witnessLen >= 2 {
		controlIdx := witnessLen - 1
		if hasAnnex {
			controlIdx = witnessLen - 1
		}
		controlBlock := witness[controlIdx]
		if len(controlBlock) >= 33 { // minimum: 1 byte version + 32 bytes internal key
			leafVersion := controlBlock[0] & 0xfe
			if leafVersion == 0xc0 {
				return InputTypeP2TR_Script
			}
		}
	}

	return InputTypeUnknown
}

// classifyP2SHSpend classifies a P2SH spend as nested SegWit or plain P2SH.
func classifyP2SHSpend(scriptSig []byte, witness [][]byte) InputScriptType {
	// Extract the redeemScript (last push in scriptSig)
	redeemScript := extractLastPush(scriptSig)
	if redeemScript == nil {
		return InputTypeUnknown
	}

	redeemType := ClassifyScript(redeemScript)

	switch redeemType {
	case ScriptTypeP2WPKH:
		// P2SH-P2WPKH: redeemScript is 0014<20>, witness has 2 items
		if len(witness) == 2 {
			return InputTypeP2SH_P2WPKH
		}
	case ScriptTypeP2WSH:
		// P2SH-P2WSH: redeemScript is 0020<32>, witness has items
		if len(witness) >= 1 {
			return InputTypeP2SH_P2WSH
		}
	}

	return InputTypeUnknown
}

// extractLastPush extracts the last data push from a script.
func extractLastPush(script []byte) []byte {
	if len(script) == 0 {
		return nil
	}

	var lastPush []byte
	i := 0
	for i < len(script) {
		op := script[i]
		i++

		// Direct push: 0x01-0x4b
		if op >= 0x01 && op <= 0x4b {
			pushLen := int(op)
			if i+pushLen > len(script) {
				return nil
			}
			lastPush = script[i : i+pushLen]
			i += pushLen
			continue
		}

		// OP_PUSHDATA1
		if op == byte(OP_PUSHDATA1) {
			if i >= len(script) {
				return nil
			}
			pushLen := int(script[i])
			i++
			if i+pushLen > len(script) {
				return nil
			}
			lastPush = script[i : i+pushLen]
			i += pushLen
			continue
		}

		// OP_PUSHDATA2
		if op == byte(OP_PUSHDATA2) {
			if i+2 > len(script) {
				return nil
			}
			pushLen := int(binary.LittleEndian.Uint16(script[i : i+2]))
			i += 2
			if i+pushLen > len(script) {
				return nil
			}
			lastPush = script[i : i+pushLen]
			i += pushLen
			continue
		}

		// OP_PUSHDATA4
		if op == byte(OP_PUSHDATA4) {
			if i+4 > len(script) {
				return nil
			}
			pushLen := int(binary.LittleEndian.Uint32(script[i : i+4]))
			i += 4
			if i+pushLen > len(script) {
				return nil
			}
			lastPush = script[i : i+pushLen]
			i += pushLen
			continue
		}

		// OP_0 pushes empty
		if op == byte(OP_0) {
			lastPush = []byte{}
			continue
		}

		// Other opcodes - just continue (shouldn't be in scriptSig normally)
	}

	return lastPush
}

// GetWitnessScript returns the witnessScript from a P2WSH or P2SH-P2WSH witness.
// Returns nil if the input type doesn't have a witnessScript.
func GetWitnessScript(inputType InputScriptType, witness [][]byte) []byte {
	if len(witness) == 0 {
		return nil
	}

	switch inputType {
	case InputTypeP2WSH, InputTypeP2SH_P2WSH:
		// Last witness item is the witnessScript
		return witness[len(witness)-1]
	default:
		return nil
	}
}

