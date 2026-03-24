package models

// Block represents a parsed Bitcoin block
type Block struct {
	Hash       string          `json:"block_hash"`
	Height     int64           `json:"block_height"`
	Timestamp  int64           `json:"timestamp"`
	TxCount    int             `json:"tx_count"`
	Txs        []Transaction   `json:"-"`
	RawHash    [32]byte        `json:"-"`
	PrevHash   [32]byte        `json:"-"`
	MerkleRoot [32]byte        `json:"-"`
}

// Transaction represents a Bitcoin transaction
type Transaction struct {
	TxID             string              `json:"txid"`
	Version          int32               `json:"version,omitempty"`
	Inputs           []Input             `json:"inputs,omitempty"`
	Outputs          []Output            `json:"outputs,omitempty"`
	LockTime         uint32              `json:"locktime,omitempty"`
	Heuristics       HeuristicsResult    `json:"heuristics"`
	Classification   string              `json:"classification"`
	FeeRateSatVB     float64             `json:"fee_rate_sat_vb,omitempty"`
	IsCoinbase       bool                `json:"-"`
	TotalInputValue  int64               `json:"-"`
	TotalOutputValue int64               `json:"-"`
}

// Input represents a transaction input
type Input struct {
	PrevTxID     string      `json:"prev_txid"`
	PrevOutIndex uint32      `json:"prev_out_index"`
	Script       []byte      `json:"script,omitempty"`
	Sequence     uint32      `json:"sequence,omitempty"`
	Value        int64       `json:"value,omitempty"`
	ScriptType   string      `json:"script_type,omitempty"`
	Address      string      `json:"address,omitempty"`
}

// Output represents a transaction output
type Output struct {
	Index      int    `json:"index"`
	Value      int64  `json:"value"`
	Script     []byte `json:"script,omitempty"`
	ScriptType string `json:"script_type"`
	Address    string `json:"address,omitempty"`
	IsChange   bool   `json:"is_change,omitempty"`
}

// HeuristicsResult contains results of all heuristics applied to a transaction
type HeuristicsResult map[string]interface{}

// AnalysisSummary aggregates statistics about chain analysis results
type AnalysisSummary struct {
	TotalTransactionsAnalyzed int                       `json:"total_transactions_analyzed"`
	HeuristicsApplied         []string                  `json:"heuristics_applied"`
	FlaggedTransactions       int                       `json:"flagged_transactions"`
	ScriptTypeDistribution    map[string]int            `json:"script_type_distribution"`
	FeeRateStats              FeeRateStats              `json:"fee_rate_stats"`
}

// FeeRateStats provides min/max/median/mean fee rates
type FeeRateStats struct {
	MinSatVB    float64 `json:"min_sat_vb"`
	MaxSatVB    float64 `json:"max_sat_vb"`
	MedianSatVB float64 `json:"median_sat_vb"`
	MeanSatVB   float64 `json:"mean_sat_vb"`
}

// BlockAnalysis represents the analysis results for a single block
type BlockAnalysis struct {
	Block            Block              `json:"block"`
	Transactions     []Transaction      `json:"transactions"`
	AnalysisSummary  AnalysisSummary    `json:"analysis_summary"`
}

// FileAnalysisResult represents the complete analysis result for a block file
type FileAnalysisResult struct {
	OK               bool                   `json:"ok"`
	Mode             string                 `json:"mode"`
	File             string                 `json:"file"`
	BlockCount       int                    `json:"block_count"`
	AnalysisSummary  AnalysisSummary        `json:"analysis_summary"`
	Blocks           []BlockAnalysisCompact `json:"blocks"`
}

// BlockAnalysisCompact is the compact per-block structure for JSON output
type BlockAnalysisCompact struct {
	BlockHash       string          `json:"block_hash"`
	BlockHeight     int64           `json:"block_height"`
	TxCount         int             `json:"tx_count"`
	AnalysisSummary AnalysisSummary `json:"analysis_summary"`
	Transactions    []Transaction   `json:"transactions"`
}
