// Package models defines JSON input schema for Chain Lens fixtures.
package models

// Fixture represents the input JSON fixture for single transaction analysis.
type Fixture struct {
	Network  string           `json:"network"`
	RawTx    string           `json:"raw_tx"`
	Prevouts []FixturePrevout `json:"prevouts"`
}

// FixturePrevout represents a prevout in the fixture input.
type FixturePrevout struct {
	Txid            string `json:"txid"`
	Vout            uint32 `json:"vout"`
	ValueSats       uint64 `json:"value_sats"`
	ScriptPubkeyHex string `json:"script_pubkey_hex"`
}

// OutPoint uniquely identifies a transaction output.
type OutPoint struct {
	Txid string
	Vout uint32
}

// NewOutPoint creates an OutPoint from txid and vout.
func NewOutPoint(txid string, vout uint32) OutPoint {
	return OutPoint{Txid: txid, Vout: vout}
}

// PrevoutMap is a map from outpoint to prevout data for efficient lookup.
type PrevoutMap map[OutPoint]FixturePrevout

// BuildPrevoutMap constructs a prevout lookup map from fixture prevouts.
// Returns an error if there are duplicate entries.
func BuildPrevoutMap(prevouts []FixturePrevout) (PrevoutMap, error) {
	m := make(PrevoutMap, len(prevouts))
	for _, p := range prevouts {
		op := NewOutPoint(p.Txid, p.Vout)
		if _, exists := m[op]; exists {
			return nil, NewAnalysisErrorf(ErrCodeDuplicatePrevout,
				"duplicate prevout: txid=%s vout=%d", p.Txid, p.Vout)
		}
		m[op] = p
	}
	return m, nil
}

// Network constants.
const (
	NetworkMainnet = "mainnet"
	NetworkTestnet = "testnet"
	NetworkRegtest = "regtest"
	NetworkSignet  = "signet"
)

// ValidNetworks is the set of valid network values.
var ValidNetworks = map[string]bool{
	NetworkMainnet: true,
	NetworkTestnet: true,
	NetworkRegtest: true,
	NetworkSignet:  true,
}

// Validate checks that the fixture has all required fields.
func (f *Fixture) Validate() error {
	if f.Network == "" {
		return NewAnalysisErrorf(ErrCodeMissingField, "missing required field: network")
	}
	if !ValidNetworks[f.Network] {
		return NewAnalysisErrorf(ErrCodeInvalidFixture, "invalid network: %s", f.Network)
	}
	if f.RawTx == "" {
		return NewAnalysisErrorf(ErrCodeMissingField, "missing required field: raw_tx")
	}
	// prevouts can be empty only for coinbase transactions, but we validate that later
	return nil
}
