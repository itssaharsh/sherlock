package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sherlock/internal/analysis"
	"sherlock/internal/models"
	"sort"
	"strings"
	"time"
)

// Formatter handles JSON and Markdown output generation
type Formatter struct {
	blocks []*models.Block
}

// NewFormatter creates a new formatter
func NewFormatter(blocks []*models.Block) *Formatter {
	return &Formatter{blocks: blocks}
}

// WriteJSON writes the analysis results to a JSON file
func (f *Formatter) WriteJSON(filename string, outDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	result := f.buildFileAnalysisResult(filename)

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	outPath := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))+".json")
	if err := os.WriteFile(outPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// WriteMarkdown writes the analysis results to a Markdown file
func (f *Formatter) WriteMarkdown(filename string, outDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var buf bytes.Buffer

	// Header
	stem := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	fmt.Fprintf(&buf, "# Chain Analysis Report: %s\n\n", stem)
	fmt.Fprintf(&buf, "**Generated:** %s\n\n", time.Now().Format(time.RFC3339))

	// File overview
	fmt.Fprintf(&buf, "## 📄 File Overview\n\n")
	fmt.Fprintf(&buf, "- **Source File:** %s\n", filepath.Base(filename))
	fmt.Fprintf(&buf, "- **Blocks Analyzed:** %d\n", len(f.blocks))

	totalTxs := 0
	for _, block := range f.blocks {
		totalTxs += block.TxCount
	}
	fmt.Fprintf(&buf, "- **Total Transactions:** %d\n\n", totalTxs)

	// Calculate aggregate statistics
	aggStats := f.calculateAggregateStats()

	// Summary statistics
	fmt.Fprintf(&buf, "## 📊 Summary Statistics\n\n")

	fmt.Fprintf(&buf, "### Heuristic Coverage\n\n")
	fmt.Fprintf(&buf, "The following chain analysis heuristics were applied:\n\n")
	for _, h := range analysis.GetHeuristicsApplied() {
		fmt.Fprintf(&buf, "- **%s**\n", formatHeuristicName(h))
	}
	fmt.Fprintf(&buf, "\n")

	fmt.Fprintf(&buf, "### Fee Rate Distribution\n\n")
	stats := aggStats.FeeRateStats
	fmt.Fprintf(&buf, "| Metric | Value |\n")
	fmt.Fprintf(&buf, "|--------|-------|\n")
	fmt.Fprintf(&buf, "| Minimum | %.2f sat/vB |\n", stats.MinSatVB)
	fmt.Fprintf(&buf, "| Maximum | %.2f sat/vB |\n", stats.MaxSatVB)
	fmt.Fprintf(&buf, "| Median | %.2f sat/vB |\n", stats.MedianSatVB)
	fmt.Fprintf(&buf, "| Mean | %.2f sat/vB |\n\n", stats.MeanSatVB)

	fmt.Fprintf(&buf, "### Script Type Distribution\n\n")
	fmt.Fprintf(&buf, "| Script Type | Count |\n")
	fmt.Fprintf(&buf, "|-------------|-------|\n")
	scriptTypes := make([]string, 0, len(aggStats.ScriptTypeDistribution))
	for st := range aggStats.ScriptTypeDistribution {
		scriptTypes = append(scriptTypes, st)
	}
	sort.Strings(scriptTypes)
	for _, st := range scriptTypes {
		count := aggStats.ScriptTypeDistribution[st]
		fmt.Fprintf(&buf, "| %s | %d |\n", st, count)
	}
	fmt.Fprintf(&buf, "\n")

	fmt.Fprintf(&buf, "### Flagged Transactions\n\n")
	fmt.Fprintf(&buf, "**Total Flagged:** %d transactions show heuristic signatures\n\n", aggStats.FlaggedTransactions)

	// Per-block sections
	for blockNum, block := range f.blocks {
		fmt.Fprintf(&buf, "## 📦 Block %d\n\n", blockNum+1)
		fmt.Fprintf(&buf, "- **Hash:** `%s`\n", block.Hash)
		fmt.Fprintf(&buf, "- **Height:** %d\n", block.Height)
		fmt.Fprintf(&buf, "- **Timestamp:** %s\n", time.Unix(block.Timestamp, 0).Format(time.RFC3339))
		fmt.Fprintf(&buf, "- **Transactions:** %d\n\n", block.TxCount)

		// Heuristic findings per block
		fmt.Fprintf(&buf, "### Heuristic Findings\n\n")

		blockStats := f.analyzeBlockHeuristics(block)
		for heuristic, count := range blockStats {
			if count > 0 {
				fmt.Fprintf(&buf, "- **%s:** %d transactions\n", formatHeuristicName(heuristic), count)
			}
		}
		fmt.Fprintf(&buf, "\n")

		// Notable transactions
		notableTxs := f.findNotableTransactions(block)
		if len(notableTxs) > 0 {
			fmt.Fprintf(&buf, "### Notable Transactions\n\n")
			for _, tx := range notableTxs {
				fmt.Fprintf(&buf, "#### %s\n\n", tx.TxID[:16]+"...")
				fmt.Fprintf(&buf, "- **Classification:** %s\n", tx.Classification)
				fmt.Fprintf(&buf, "- **Inputs:** %d, **Outputs:** %d\n", len(tx.Inputs), len(tx.Outputs))

				// Summarize main findings
				if ciohResult, ok := tx.Heuristics["cioh"].(map[string]interface{}); ok {
					if ciohResult["detected"].(bool) {
						fmt.Fprintf(&buf, "- 🔗 Multiple inputs suggest CIOH\n")
					}
				}

				if changeResult, ok := tx.Heuristics["change_detection"].(map[string]interface{}); ok {
					if changeResult["detected"].(bool) {
						fmt.Fprintf(&buf, "- 💱 Likely change output detected\n")
					}
				}

				if coinjoinResult, ok := tx.Heuristics["coinjoin"].(map[string]interface{}); ok {
					if coinjoinResult["detected"].(bool) {
						fmt.Fprintf(&buf, "- 🎲 CoinJoin-like pattern detected\n")
					}
				}

				fmt.Fprintf(&buf, "\n")
			}
		}
	}

	// Write to file
	outPath := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))+".md")
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write Markdown file: %w", err)
	}

	return nil
}

// buildFileAnalysisResult builds the complete file analysis result
func (f *Formatter) buildFileAnalysisResult(filename string) *models.FileAnalysisResult {
	result := &models.FileAnalysisResult{
		OK:         true,
		Mode:       "chain_analysis",
		File:       filepath.Base(filename),
		BlockCount: len(f.blocks),
		Blocks:     make([]models.BlockAnalysisCompact, len(f.blocks)),
	}

	var allTxs []models.Transaction
	for i, block := range f.blocks {
		blockCompact := models.BlockAnalysisCompact{
			BlockHash:    block.Hash,
			BlockHeight:  block.Height,
			TxCount:      block.TxCount,
			Transactions: make([]models.Transaction, len(block.Txs)),
		}

		// Copy transactions for first block, omit for others
		if i == 0 {
			for j := range block.Txs {
				blockCompact.Transactions[j] = block.Txs[j]
				allTxs = append(allTxs, block.Txs[j])
			}
		} else {
			allTxs = append(allTxs, block.Txs...)
		}

		// Calculate block summary
		blockCompact.AnalysisSummary = f.buildAnalysisSummary(block.Txs)

		result.Blocks[i] = blockCompact
	}

	// Calculate file-level summary
	result.AnalysisSummary = f.buildAnalysisSummary(allTxs)

	return result
}

// buildAnalysisSummary builds an analysis summary for a list of transactions
func (f *Formatter) buildAnalysisSummary(txs []models.Transaction) models.AnalysisSummary {
	summary := models.AnalysisSummary{
		TotalTransactionsAnalyzed: len(txs),
		HeuristicsApplied:         analysis.GetHeuristicsApplied(),
		FlaggedTransactions:       analysis.CountFlaggedTransactions(txs),
		ScriptTypeDistribution:    analysis.GetScriptTypeDistribution(txs),
		FeeRateStats:              analysis.CalculateFeeRateStats(txs),
	}

	// Ensure script type distribution has all types
	allTypes := []string{"p2wpkh", "p2tr", "p2sh", "p2pkh", "p2wsh", "op_return", "unknown"}
	for _, t := range allTypes {
		if _, ok := summary.ScriptTypeDistribution[t]; !ok {
			summary.ScriptTypeDistribution[t] = 0
		}
	}

	return summary
}

// calculateAggregateStats calculates statistics across all blocks
func (f *Formatter) calculateAggregateStats() models.AnalysisSummary {
	var allTxs []models.Transaction
	for _, block := range f.blocks {
		allTxs = append(allTxs, block.Txs...)
	}
	return f.buildAnalysisSummary(allTxs)
}

// analyzeBlockHeuristics returns counts of heuristics detected per block
func (f *Formatter) analyzeBlockHeuristics(block *models.Block) map[string]int {
	counts := make(map[string]int)
	for _, h := range analysis.GetHeuristicsApplied() {
		counts[h] = 0
	}

	for _, tx := range block.Txs {
		for heuristic, result := range tx.Heuristics {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if detected, ok := resultMap["detected"].(bool); ok && detected {
					counts[heuristic]++
				}
			}
		}
	}

	return counts
}

// findNotableTransactions returns interesting transactions from the block
func (f *Formatter) findNotableTransactions(block *models.Block) []models.Transaction {
	var notable []models.Transaction

	for _, tx := range block.Txs {
		// Include transactions with interesting classifications
		switch tx.Classification {
		case "coinjoin", "consolidation", "self_transfer":
			notable = append(notable, tx)
		default:
			// Include other high-heuristic-count transactions
			count := 0
			for _, result := range tx.Heuristics {
				if resultMap, ok := result.(map[string]interface{}); ok {
					if detected, ok := resultMap["detected"].(bool); ok && detected {
						count++
					}
				}
			}
			if count >= 3 {
				notable = append(notable, tx)
			}
		}

		// Limit to 5 most notable per block
		if len(notable) >= 5 {
			break
		}
	}

	return notable
}

// formatHeuristicName formats heuristic IDs to readable names
func formatHeuristicName(id string) string {
	names := map[string]string{
		"cioh":                   "Common Input Ownership Heuristic",
		"change_detection":       "Change Detection",
		"address_reuse":          "Address Reuse",
		"coinjoin":               "CoinJoin Detection",
		"consolidation":          "Consolidation Detection",
		"self_transfer":          "Self-Transfer Detection",
		"peeling_chain":          "Peeling Chain Detection",
		"op_return":              "OP_RETURN Analysis",
		"round_number_payment":   "Round Number Payment",
	}

	if name, ok := names[id]; ok {
		return name
	}
	return id
}
