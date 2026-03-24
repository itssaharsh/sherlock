package analysis

import (
	"math"
	"sherlock/internal/models"
	"sort"
)

// Analyzer performs chain analysis on transactions
type Analyzer struct {
	blocks []*models.Block
	txMap  map[string]*models.Transaction
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(blocks []*models.Block) *Analyzer {
	a := &Analyzer{
		blocks: blocks,
		txMap:  make(map[string]*models.Transaction),
	}
	for _, block := range blocks {
		for i := range block.Txs {
			a.txMap[block.Txs[i].TxID] = &block.Txs[i]
		}
	}
	return a
}

// AnalyzeBlocks analyzes all blocks and applies heuristics
func (a *Analyzer) AnalyzeBlocks() error {
	for _, block := range a.blocks {
		for i := range block.Txs {
			a.analyzeTx(&block.Txs[i])
		}
	}
	return nil
}

// analyzeTx applies all heuristics to a transaction
func (a *Analyzer) analyzeTx(tx *models.Transaction) {
	if tx.Heuristics == nil {
		tx.Heuristics = make(map[string]interface{})
	}

	// Apply mandatory heuristics
	a.applyCIOH(tx)
	a.applyChangeDetection(tx)

	// Apply optional heuristics
	a.applyAddressReuse(tx)
	a.applyCoinJoinDetection(tx)
	a.applyConsolidationDetection(tx)
	a.applySelfTransferDetection(tx)
	a.applyPeelingChainDetection(tx)
	a.applyOpReturnAnalysis(tx)
	a.applyRoundNumberPayment(tx)

	// Classify transaction
	a.classifyTransaction(tx)
}

// applyCIOH - Common Input Ownership Heuristic
func (a *Analyzer) applyCIOH(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": len(tx.Inputs) > 1,
	}
	if len(tx.Inputs) > 1 {
		result["input_count"] = len(tx.Inputs)
		result["assumption"] = "All %d inputs likely controlled by same entity"
	}
	tx.Heuristics["cioh"] = result
}

// applyChangeDetection identifies likely change outputs
func (a *Analyzer) applyChangeDetection(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": false,
	}

	if len(tx.Outputs) < 2 || len(tx.Inputs) == 0 {
		tx.Heuristics["change_detection"] = result
		return
	}

	// Strategy 1: Script type matching (input and output of same type)
	inputTypes := make(map[string]int)
	for _, inp := range tx.Inputs {
		inputTypes[inp.ScriptType]++
	}

	// Find output matching most common input type
	for inputType, count := range inputTypes {
		for _, out := range tx.Outputs {
			if out.ScriptType == inputType {
				confidence := a.calculateChangeConfidence(tx, out, inputType, count)
				result["detected"] = true
				result["likely_change_index"] = out.Index
				result["method"] = "script_type_match"
				result["confidence"] = confidence
				break
			}
		}
		if result["detected"].(bool) {
			break
		}
	}

	// Strategy 2: Round number detection
	if !result["detected"].(bool) {
		for _, out := range tx.Outputs {
			if isRoundAmount(out.Value) {
				// This is likely a payment, not change
				continue
			}
		}
	}

	tx.Heuristics["change_detection"] = result
}

// applyAddressReuse detects address reuse
func (a *Analyzer) applyAddressReuse(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": false,
		"reused":   []string{},
	}

	addresses := make(map[string]int)

	// Collect all addresses
	for _, inp := range tx.Inputs {
		if inp.Address != "" {
			addresses[inp.Address]++
		}
	}

	for _, out := range tx.Outputs {
		if out.Address != "" {
			if addresses[out.Address] > 0 {
				result["detected"] = true
				result["reused"] = append(result["reused"].([]string), out.Address)
			}
		}
	}

	tx.Heuristics["address_reuse"] = result
}

// applyCoinJoinDetection detects coinjoin-like transactions
func (a *Analyzer) applyCoinJoinDetection(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": false,
	}

	if len(tx.Inputs) < 2 || len(tx.Outputs) < 2 {
		tx.Heuristics["coinjoin"] = result
		return
	}

	// Count equal-value outputs
	outputValues := make(map[int64]int)
	for _, out := range tx.Outputs {
		if out.Value > 0 {
			outputValues[out.Value]++
		}
	}

	// If multiple outputs have equal value, likely coinjoin
	detected := false
	var equalValueCount int
	for _, count := range outputValues {
		if count > 1 {
			detected = true
			equalValueCount = count
			break
		}
	}

	if detected && len(tx.Inputs) >= 3 {
		result["detected"] = true
		result["equal_value_outputs"] = equalValueCount
		result["input_count"] = len(tx.Inputs)
		result["confidence"] = "medium"
	}

	tx.Heuristics["coinjoin"] = result
}

// applyConsolidationDetection detects consolidation transactions
func (a *Analyzer) applyConsolidationDetection(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": false,
	}

	// Consolidation: many inputs, few outputs (typically 1-2)
	if len(tx.Inputs) >= 3 && len(tx.Outputs) <= 2 {
		result["detected"] = true
		result["input_count"] = len(tx.Inputs)
		result["output_count"] = len(tx.Outputs)

		// Check if all outputs same script type
		if len(tx.Outputs) > 0 {
			scriptType := tx.Outputs[0].ScriptType
			allSameType := true
			for i := 1; i < len(tx.Outputs); i++ {
				if tx.Outputs[i].ScriptType != scriptType {
					allSameType = false
					break
				}
			}
			result["same_script_type"] = allSameType
		}
	}

	tx.Heuristics["consolidation"] = result
}

// applySelfTransferDetection detects self-transfers
func (a *Analyzer) applySelfTransferDetection(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": false,
	}

	if len(tx.Inputs) < 1 || len(tx.Outputs) < 1 {
		tx.Heuristics["self_transfer"] = result
		return
	}

	// Check if all outputs match input script types
	inputTypes := make(map[string]bool)
	for _, inp := range tx.Inputs {
		inputTypes[inp.ScriptType] = true
	}

	allMatch := true
	for _, out := range tx.Outputs {
		if !inputTypes[out.ScriptType] && out.ScriptType != "op_return" {
			allMatch = false
			break
		}
	}

	if allMatch && len(tx.Inputs) == len(tx.Outputs) {
		result["detected"] = true
		result["confidence"] = "high"
	}

	tx.Heuristics["self_transfer"] = result
}

// applyPeelingChainDetection detects peeling chain patterns
func (a *Analyzer) applyPeelingChainDetection(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected": false,
	}

	// Peeling chain: one large input split into one small output + one large output
	if len(tx.Inputs) == 1 && len(tx.Outputs) == 2 {
		// One output is much larger than the other (likely payment + change pattern)
		amounts := []int64{tx.Outputs[0].Value, tx.Outputs[1].Value}
		sort.Slice(amounts, func(i, j int) bool { return amounts[i] < amounts[j] })

		ratio := float64(amounts[1]) / float64(amounts[0])
		if ratio > 2.0 {
			result["detected"] = true
			result["small_output_value"] = amounts[0]
			result["large_output_value"] = amounts[1]
		}
	}

	tx.Heuristics["peeling_chain"] = result
}

// applyOpReturnAnalysis detects OP_RETURN outputs
func (a *Analyzer) applyOpReturnAnalysis(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected":    false,
		"op_returns":  []string{},
		"data_length": 0,
	}

	opReturnCount := 0
	totalDataLen := 0

	for _, out := range tx.Outputs {
		if out.ScriptType == "op_return" && len(out.Script) > 0 {
			opReturnCount++
			totalDataLen += len(out.Script)
			// Try to identify protocol
			protocol := identifyProtocol(out.Script)
			result["op_returns"] = append(result["op_returns"].([]string), protocol)
		}
	}

	if opReturnCount > 0 {
		result["detected"] = true
		result["op_return_count"] = opReturnCount
		result["data_length"] = totalDataLen
	}

	tx.Heuristics["op_return"] = result
}

// applyRoundNumberPayment detects round number outputs
func (a *Analyzer) applyRoundNumberPayment(tx *models.Transaction) {
	result := map[string]interface{}{
		"detected":       false,
		"round_outputs":  []int{},
	}

	roundOutputs := []int{}
	for i, out := range tx.Outputs {
		if isRoundAmount(out.Value) {
			roundOutputs = append(roundOutputs, i)
		}
	}

	if len(roundOutputs) > 0 {
		result["detected"] = true
		result["round_outputs"] = roundOutputs
		result["count"] = len(roundOutputs)
	}

	tx.Heuristics["round_number_payment"] = result
}

// classifyTransaction assigns a classification to the transaction
func (a *Analyzer) classifyTransaction(tx *models.Transaction) {
	// Start with unknown
	classification := "unknown"

	// Check heuristic results
	if coinjoinResult, ok := tx.Heuristics["coinjoin"].(map[string]interface{}); ok {
		if coinjoinResult["detected"].(bool) {
			classification = "coinjoin"
			tx.Classification = classification
			return
		}
	}

	if consolidationResult, ok := tx.Heuristics["consolidation"].(map[string]interface{}); ok {
		if consolidationResult["detected"].(bool) {
			classification = "consolidation"
			tx.Classification = classification
			return
		}
	}

	if selfTransferResult, ok := tx.Heuristics["self_transfer"].(map[string]interface{}); ok {
		if selfTransferResult["detected"].(bool) {
			classification = "self_transfer"
			tx.Classification = classification
			return
		}
	}

	// Default to simple payment
	classification = "simple_payment"
	tx.Classification = classification
}

// Helper functions

func (a *Analyzer) calculateChangeConfidence(tx *models.Transaction, out models.Output, scriptType string, matchingInputCount int) string {
	confidence := "low"

	// Increase confidence based on:
	// 1. Percentage of inputs matching output type
	matchRatio := float64(matchingInputCount) / float64(len(tx.Inputs))
	if matchRatio > 0.8 {
		confidence = "high"
	} else if matchRatio > 0.5 {
		confidence = "medium"
	}

	// 2. Value analysis (non-round amounts more likely change)
	if !isRoundAmount(out.Value) {
		if confidence == "low" {
			confidence = "medium"
		} else if confidence == "medium" {
			confidence = "high"
		}
	}

	return confidence
}

func isRoundAmount(satoshis int64) bool {
	// Check common BTC round amounts
	btc := float64(satoshis) / 1e8
	
	// Check if it's a round number (0.1, 0.5, 1.0, 0.01, 0.001, etc.)
	round := false
	for i := -8; i <= 0; i++ {
		divisor := math.Pow(10, float64(i))
		if divisor > 0 && math.Mod(btc*1e8, float64(satoshis)) < 1 {
			rounded := math.Round(btc*divisor) / divisor
			if math.Abs(btc-rounded) < 1e-8 {
				round = true
				break
			}
		}
	}

	return round
}

func identifyProtocol(script []byte) string {
	if len(script) < 2 {
		return "unknown"
	}

	// Check for common protocols
	data := script
	if len(script) > 1 && script[0] == 0x6a {
		data = script[1:] // Skip OP_RETURN
	}

	if len(data) >= 4 {
		// Omni (0x6f6d6e69)
		if data[0] == 0x6f && data[1] == 0x6d && data[2] == 0x6e && data[3] == 0x69 {
			return "omni"
		}
		// OpenTimestamps often starts with specific magic
		if data[0] == 0x6f && data[1] == 0x70 && data[2] == 0x65 && data[3] == 0x6e {
			return "opentimestamps"
		}
	}

	return "data"
}

// GetHeuristicsApplied returns the list of heuristics applied
func GetHeuristicsApplied() []string {
	return []string{
		"cioh",
		"change_detection",
		"address_reuse",
		"coinjoin",
		"consolidation",
		"self_transfer",
		"peeling_chain",
		"op_return",
		"round_number_payment",
	}
}

// CountFlaggedTransactions counts transactions with detected heuristics
func CountFlaggedTransactions(txs []models.Transaction) int {
	count := 0
	for _, tx := range txs {
		for _, result := range tx.Heuristics {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if detected, ok := resultMap["detected"].(bool); ok && detected {
					count++
					break // Count once per tx
				}
			}
		}
	}
	return count
}

// GetScriptTypeDistribution returns distribution of script types
func GetScriptTypeDistribution(txs []models.Transaction) map[string]int {
	dist := make(map[string]int)
	for _, tx := range txs {
		for _, out := range tx.Outputs {
			dist[out.ScriptType]++
		}
	}
	return dist
}

// CalculateFeeRateStats calculates fee rate statistics
func CalculateFeeRateStats(txs []models.Transaction) models.FeeRateStats {
	var feeRates []float64

	for _, tx := range txs {
		if !tx.IsCoinbase && len(tx.Inputs) > 0 {
			// Fee = inputs - outputs (in satoshis)
			fee := tx.TotalInputValue - tx.TotalOutputValue
			if fee < 0 {
				fee = 0
			}

			// Calculate vbytes (simplified)
			vbytes := float64(len(tx.TxID)) / 2 // Rough estimate
			if vbytes > 0 {
				feeRate := float64(fee) / vbytes
				if feeRate >= 0 {
					feeRates = append(feeRates, feeRate)
				}
			}
		}
	}

	stats := models.FeeRateStats{
		MinSatVB:    0,
		MaxSatVB:    0,
		MedianSatVB: 0,
		MeanSatVB:   0,
	}

	if len(feeRates) == 0 {
		return stats
	}

	sort.Float64s(feeRates)

	// Min and Max
	stats.MinSatVB = feeRates[0]
	stats.MaxSatVB = feeRates[len(feeRates)-1]

	// Median
	if len(feeRates)%2 == 0 {
		stats.MedianSatVB = (feeRates[len(feeRates)/2-1] + feeRates[len(feeRates)/2]) / 2
	} else {
		stats.MedianSatVB = feeRates[len(feeRates)/2]
	}

	// Mean
	sum := 0.0
	for _, rate := range feeRates {
		sum += rate
	}
	stats.MeanSatVB = sum / float64(len(feeRates))

	return stats
}
