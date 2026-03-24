package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sherlock/internal/analysis"
	"sherlock/internal/models"
	"sherlock/internal/output"
	"sherlock/internal/parser"
)

func main() {
	// Parse command line arguments
	if len(os.Args) < 2 {
		printError("missing_command", "usage: cli.sh --block <blk.dat> <rev.dat> <xor.dat>")
		os.Exit(1)
	}

	if os.Args[1] == "--block" {
		if len(os.Args) < 5 {
			printError("missing_arguments", "usage: --block <blk.dat> <rev.dat> <xor.dat>")
			os.Exit(1)
		}

		blockFile := os.Args[2]
		revFile := os.Args[3]
		xorFile := os.Args[4]

		if err := analyzeBlock(blockFile, revFile, xorFile); err != nil {
			printError("analysis_failed", err.Error())
			os.Exit(1)
		}
	} else {
		printError("unknown_command", fmt.Sprintf("unknown command: %s", os.Args[1]))
		os.Exit(1)
	}
}

func analyzeBlock(blockFile, revFile, xorFile string) error {
	// Read block file
	blockData, err := os.ReadFile(blockFile)
	if err != nil {
		return fmt.Errorf("failed to read block file: %w", err)
	}

	// Parse blocks using Challenge 1 parser
	blockEntries, err := parser.ParseBlockFile(blockData)
	if err != nil {
		return fmt.Errorf("failed to parse block file: %w", err)
	}

	if len(blockEntries) == 0 {
		return fmt.Errorf("no blocks found in file")
	}

	// Convert BlockFileEntry to our models
	blocks := make([]*models.Block, len(blockEntries))
	for i, entry := range blockEntries {
		// Parse transactions from raw block data
		txs, err := parser.ParseBlockTransactions(entry.RawData)
		if err != nil {
			return fmt.Errorf("failed to parse transactions in block %d: %w", i, err)
		}

		block := &models.Block{
			Hash:       entry.Header.BlockHash(),
			Height:     0, // Will extract from coinbase
			Timestamp:  int64(entry.Header.Timestamp),
			TxCount:    len(txs),
			Txs:        convertTransactions(txs),
		}

		// Extract block height from coinbase
		if len(txs) > 0 && txs[0] != nil {
			if len(txs[0].Inputs) > 0 {
				height := decodeBIP34Height(txs[0].Inputs[0].ScriptSig)
				block.Height = height
			}
		}

		blocks[i] = block
	}

	// Analyze blocks
	analyzer := analysis.NewAnalyzer(blocks)
	if err := analyzer.AnalyzeBlocks(); err != nil {
		return fmt.Errorf("failed to analyze blocks: %w", err)
	}

	// Format and write outputs
	formatter := output.NewFormatter(blocks)

	// Create out directory if needed
	if err := os.MkdirAll("out", 0755); err != nil {
		return fmt.Errorf("failed to create out directory: %w", err)
	}

	// Write JSON
	if err := formatter.WriteJSON(blockFile, "out"); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	// Write Markdown
	if err := formatter.WriteMarkdown(blockFile, "out"); err != nil {
		return fmt.Errorf("failed to write Markdown: %w", err)
	}

	return nil
}

// Helper functions

func convertTransactions(txs []*parser.RawTransaction) []models.Transaction {
	result := make([]models.Transaction, len(txs))
	for i, tx := range txs {
		result[i] = convertTransaction(tx)
	}
	return result
}

func convertTransaction(tx *parser.RawTransaction) models.Transaction {
	result := models.Transaction{
		TxID:    tx.Txid(),
		Version: tx.Version,
		Inputs:  convertInputs(tx.Inputs),
		Outputs: convertOutputs(tx.Outputs),
		LockTime: tx.Locktime,
		IsCoinbase: len(tx.Inputs) == 1 && tx.Inputs[0].PrevVout == 0xffffffff,
		Heuristics: make(map[string]interface{}),
	}

	// Calculate output value for fee analysis
	totalOut := uint64(0)
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	result.TotalOutputValue = int64(totalOut)

	// Calculate fee rate (simplified - we don't have input values)
	vbytes := float64(tx.TotalSize) / 4 // Simplified vbyte
	if vbytes > 0 {
		result.FeeRateSatVB = float64(totalOut) / vbytes // Simplified
	}

	return result
}

func convertInputs(inputs []parser.RawInput) []models.Input {
	result := make([]models.Input, len(inputs))
	for i, inp := range inputs {
		// PrevTxid is a [32]byte array; pass it directly
		prevTxHex := reverseHex(inp.PrevTxid)
		result[i] = models.Input{
			PrevTxID:     prevTxHex,
			PrevOutIndex: inp.PrevVout,
			Script:       inp.ScriptSig,
			Sequence:     inp.Sequence,
			ScriptType:   classifyScript(inp.ScriptSig),
		}
	}
	return result
}

func reverseHex(data [32]byte) string {
	bytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		bytes[31-i] = data[i]
	}
	return fmt.Sprintf("%x", bytes)
}

func convertOutputs(outputs []parser.RawOutput) []models.Output {
	result := make([]models.Output, len(outputs))
	for i, out := range outputs {
		scriptType := classifyScript(out.ScriptPubkey)
		result[i] = models.Output{
			Index:      i,
			Value:      int64(out.Value),
			Script:     out.ScriptPubkey,
			ScriptType: scriptType,
			Address:    extractAddress(out.ScriptPubkey, scriptType),
		}
	}
	return result
}

func classifyScript(script []byte) string {
	if len(script) == 0 {
		return "unknown"
	}

	// P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	if len(script) == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 {
		return "p2pkh"
	}

	// P2SH: OP_HASH160 <20 bytes> OP_EQUAL
	if len(script) == 23 && script[0] == 0xa9 && script[1] == 0x14 {
		return "p2sh"
	}

	// P2WPKH: OP_0 <20 bytes>
	if len(script) == 22 && script[0] == 0x00 && script[1] == 0x14 {
		return "p2wpkh"
	}

	// P2WSH: OP_0 <32 bytes>
	if len(script) == 34 && script[0] == 0x00 && script[1] == 0x20 {
		return "p2wsh"
	}

	// P2TR: OP_1 <32 bytes>
	if len(script) == 34 && script[0] == 0x51 && script[1] == 0x20 {
		return "p2tr"
	}

	// OP_RETURN
	if len(script) > 0 && script[0] == 0x6a {
		return "op_return"
	}

	return "unknown"
}

func extractAddress(script []byte, scriptType string) string {
	return "" // Simplified for now
}

func decodeBIP34Height(coinbaseScript []byte) int64 {
	if len(coinbaseScript) < 1 {
		return 0
	}

	scriptLen := coinbaseScript[0]
	if scriptLen == 0 || scriptLen > 4 || int(scriptLen) > len(coinbaseScript)-1 {
		return 0
	}

	height := int64(0)
	for i := 0; i < int(scriptLen); i++ {
		height |= int64(coinbaseScript[1+i]) << (8 * uint(i))
	}
	return height
}

func printError(code string, message string) {
	errResult := models.NewErrorResult(code, message)
	jsonErr, _ := json.MarshalIndent(errResult, "", "  ")
	fmt.Println(string(jsonErr))
}
