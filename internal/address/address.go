// Package address provides Bitcoin address encoding functions.
package address

import (
	"crypto/sha256"
	"errors"
	"strings"
)

// Network prefixes for mainnet
const (
	MainnetP2PKHPrefix = 0x00
	MainnetP2SHPrefix  = 0x05
	MainnetBech32HRP   = "bc"
)

// ErrInvalidData is returned when the input data is invalid for the address type.
var ErrInvalidData = errors.New("invalid data for address encoding")

// Base58 alphabet used by Bitcoin
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// EncodeP2PKH encodes a 20-byte public key hash as a P2PKH address.
func EncodeP2PKH(pubkeyHash []byte) (string, error) {
	if len(pubkeyHash) != 20 {
		return "", ErrInvalidData
	}
	return encodeBase58Check(MainnetP2PKHPrefix, pubkeyHash)
}

// EncodeP2SH encodes a 20-byte script hash as a P2SH address.
func EncodeP2SH(scriptHash []byte) (string, error) {
	if len(scriptHash) != 20 {
		return "", ErrInvalidData
	}
	return encodeBase58Check(MainnetP2SHPrefix, scriptHash)
}

// EncodeP2WPKH encodes a 20-byte witness public key hash as a P2WPKH address.
func EncodeP2WPKH(pubkeyHash []byte) (string, error) {
	if len(pubkeyHash) != 20 {
		return "", ErrInvalidData
	}
	return encodeBech32(MainnetBech32HRP, 0, pubkeyHash, false)
}

// EncodeP2WSH encodes a 32-byte witness script hash as a P2WSH address.
func EncodeP2WSH(scriptHash []byte) (string, error) {
	if len(scriptHash) != 32 {
		return "", ErrInvalidData
	}
	return encodeBech32(MainnetBech32HRP, 0, scriptHash, false)
}

// EncodeP2TR encodes a 32-byte x-only public key as a P2TR (Taproot) address.
func EncodeP2TR(xOnlyPubkey []byte) (string, error) {
	if len(xOnlyPubkey) != 32 {
		return "", ErrInvalidData
	}
	return encodeBech32(MainnetBech32HRP, 1, xOnlyPubkey, true)
}

// encodeBase58Check encodes data with a version byte using Base58Check.
func encodeBase58Check(version byte, payload []byte) (string, error) {
	// Version + payload
	data := make([]byte, 1+len(payload))
	data[0] = version
	copy(data[1:], payload)

	// Double SHA256 checksum
	hash1 := sha256.Sum256(data)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Append checksum
	data = append(data, checksum...)

	// Encode to Base58
	return encodeBase58(data), nil
}

// encodeBase58 encodes bytes to Base58.
func encodeBase58(input []byte) string {
	// Count leading zeros
	leadingZeros := 0
	for _, b := range input {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Estimate output size: log(256) / log(58) ≈ 1.37
	size := len(input)*138/100 + 1
	output := make([]byte, size)

	// Process each byte
	length := 0
	for _, b := range input {
		carry := int(b)
		i := 0
		// Apply carry to existing digits
		for j := size - 1; (carry != 0 || i < length) && j >= 0; j-- {
			carry += 256 * int(output[j])
			output[j] = byte(carry % 58)
			carry /= 58
			i++
		}
		length = i
	}

	// Skip leading zeros in output
	startIdx := size - length

	// Encode to alphabet
	var result strings.Builder
	result.Grow(leadingZeros + length)

	// Add '1' for each leading zero byte in input
	for i := 0; i < leadingZeros; i++ {
		result.WriteByte('1')
	}

	// Add encoded bytes
	for i := startIdx; i < size; i++ {
		result.WriteByte(base58Alphabet[output[i]])
	}

	return result.String()
}

// Bech32 constants
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Gen = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// encodeBech32 encodes data as a Bech32 or Bech32m address.
func encodeBech32(hrp string, witnessVersion byte, data []byte, useBech32m bool) (string, error) {
	// Convert 8-bit data to 5-bit
	converted, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Prepend witness version
	values := make([]byte, 1+len(converted))
	values[0] = witnessVersion
	copy(values[1:], converted)

	// Calculate checksum
	var checksum []byte
	if useBech32m {
		checksum = bech32mChecksum(hrp, values)
	} else {
		checksum = bech32Checksum(hrp, values)
	}

	// Append checksum
	values = append(values, checksum...)

	// Encode
	var result strings.Builder
	result.Grow(len(hrp) + 1 + len(values))
	result.WriteString(hrp)
	result.WriteByte('1')
	for _, v := range values {
		result.WriteByte(bech32Charset[v])
	}

	return result.String(), nil
}

// convertBits converts a byte slice from fromBits to toBits.
func convertBits(data []byte, fromBits, toBits int, pad bool) ([]byte, error) {
	acc := 0
	bits := 0
	maxv := (1 << toBits) - 1
	var result []byte

	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding")
	}

	return result, nil
}

// bech32Polymod calculates the Bech32 polymod.
func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

// hrpExpand expands the human-readable part for checksum calculation.
func hrpExpand(hrp string) []byte {
	result := make([]byte, len(hrp)*2+1)
	for i, c := range hrp {
		result[i] = byte(c >> 5)
		result[len(hrp)+1+i] = byte(c & 31)
	}
	result[len(hrp)] = 0
	return result
}

// bech32Checksum calculates the Bech32 checksum.
func bech32Checksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}
	return checksum
}

// bech32mChecksum calculates the Bech32m checksum.
func bech32mChecksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	// Bech32m uses constant 0x2bc830a3 instead of 1
	polymod := bech32Polymod(values) ^ 0x2bc830a3
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}
	return checksum
}
