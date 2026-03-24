// Package models defines JSON output schema for Chain Lens transaction analysis.
package models

// TransactionResult is the top-level JSON output for single transaction analysis.
type TransactionResult struct {
	OK      bool   `json:"ok"`
	Network string `json:"network"`
	Segwit  bool   `json:"segwit"`

	// Transaction identifiers
	Txid  string  `json:"txid"`
	Wtxid *string `json:"wtxid"` // nil for non-SegWit transactions

	// Basic transaction fields
	Version  int32  `json:"version"`
	Locktime uint32 `json:"locktime"`

	// Size metrics
	SizeBytes int `json:"size_bytes"`
	Weight    int `json:"weight"`
	Vbytes    int `json:"vbytes"`

	// Value accounting
	TotalInputSats  uint64  `json:"total_input_sats"`
	TotalOutputSats uint64  `json:"total_output_sats"`
	FeeSats         uint64  `json:"fee_sats"`
	FeeRateSatVB    float64 `json:"fee_rate_sat_vb"`

	// Timelock and RBF
	RBFSignaling  bool   `json:"rbf_signaling"`
	LocktimeType  string `json:"locktime_type"`  // "none", "block_height", "unix_timestamp"
	LocktimeValue uint32 `json:"locktime_value"` // raw locktime integer

	// SegWit discount analysis (nil for non-SegWit)
	SegwitSavings *SegwitSavings `json:"segwit_savings"`

	// Inputs and outputs
	Vin  []Vin  `json:"vin"`
	Vout []Vout `json:"vout"`

	// Warnings for notable conditions
	Warnings []Warning `json:"warnings"`
}

// SegwitSavings contains witness discount analysis for SegWit transactions.
type SegwitSavings struct {
	WitnessBytes    int     `json:"witness_bytes"`
	NonWitnessBytes int     `json:"non_witness_bytes"`
	TotalBytes      int     `json:"total_bytes"`
	WeightActual    int     `json:"weight_actual"`
	WeightIfLegacy  int     `json:"weight_if_legacy"`
	SavingsPct      float64 `json:"savings_pct"` // rounded to 2 decimal places
}

// Warning represents a warning condition detected in the transaction.
type Warning struct {
	Code string `json:"code"`
}

// WarningCode constants for required warning codes.
const (
	WarningHighFee             = "HIGH_FEE"
	WarningDustOutput          = "DUST_OUTPUT"
	WarningUnknownOutputScript = "UNKNOWN_OUTPUT_SCRIPT"
	WarningRBFSignaling        = "RBF_SIGNALING"
)

// LocktimeType constants for locktime classification.
const (
	LocktimeNone      = "none"
	LocktimeBlock     = "block_height"
	LocktimeTimestamp = "unix_timestamp"
)

// Locktime threshold: values < 500_000_000 are block heights, >= are timestamps.
const LocktimeThreshold uint32 = 500_000_000

// DustThreshold is the minimum satoshi value for non-OP_RETURN outputs.
const DustThreshold uint64 = 546

// HighFeeThreshold is the fee amount that triggers HIGH_FEE warning.
const HighFeeThreshold uint64 = 1_000_000

// HighFeeRateThreshold is the fee rate that triggers HIGH_FEE warning.
const HighFeeRateThreshold float64 = 200.0
