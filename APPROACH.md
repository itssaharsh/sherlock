# Sherlock: Bitcoin Chain Analysis Approach

## Overview

Sherlock is a chain analysis engine that applies transaction heuristics to Bitcoin block data to identify patterns, classify transactions, and generate insights about blockchain activity. This document outlines the implementation approach, heuristics, architecture, and design decisions.

---

## Heuristics Implemented

### 1. Common Input Ownership Heuristic (CIOH) ✓ **MANDATORY**

**What it detects:**
The CIOH assumes that when multiple inputs are spent together in a single transaction, they are likely controlled by the same entity. This is a foundational assumption in chain analysis.

**How it is detected/computed:**
- Count the number of inputs in each transaction
- Flag any transaction with 2 or more inputs as exhibiting CIOH
- Report the input count for audit purposes

**Confidence model:**
- **High:** Nearly certain — multiple inputs in a transaction are almost always controlled by the same entity with rare exceptions (e.g., multi-party payment channels, rare protocols)
- The heuristic is applied universally; confidence is not degraded even when external factors (like multiparty transactions) are present

**Limitations:**
- False positives in multiparty payment protocols or channel operations
- Doesn't account for atomic swaps or other advanced scenarios
- Assumes standard wallet behavior

---

### 2. Change Detection ✓ **MANDATORY**

**What it detects:**
Identifies the likely change output in a transaction — the output that belongs back to the sender. Change detection is crucial for understanding transaction structure and linking addresses.

**How it is detected/computed:**

Multiple strategies are applied (in priority order):

1. **Script Type Matching:**
   - Examine script types of all inputs (e.g., P2WPKH, P2TR, P2PKH)
   - Match the most common input script type to an output of the same type
   - This output is likely the change because wallets typically consolidate UTXOs of matching types

2. **Round Number Analysis (Future Enhancement):**
   - Payments are often round amounts (0.1 BTC, 0.01 BTC, 1 BTC)
   - Outputs with non-round amounts are more likely to be change
   - Not yet fully integrated but prepared for future work

3. **Output Ordering Heuristics (Future Enhancement):**
   - Some wallets place change first, others last
   - Privacy-conscious wallets randomize placement
   - Framework in place for additional ordering analysis

**Confidence model:**
- **High (>80% script type match):** When one input type dominates and a matching output exists
- **Medium (50-80% match):** When multiple script types are present but one output matches significantly
- **Low (<50% match):** When script types are mixed or ambiguous
- Additional confidence boost if output value is non-round

**Limitations:**
- Script type matching fails when wallet uses diverse UTXOs
- SegWit and taproot adoption has created more homogeneous script types but also more variation
- Privacy-focused wallets explicitly avoid patterns that make change detection easier
- CoinJoins and other privacy protocols specifically defeat this heuristic
- Edge cases: outputs to self, internal consolidations

---

### 3. Address Reuse Detection

**What it detects:**
Detects when the same address appears in both inputs and outputs of a transaction (direct reuse) or across multiple transactions within a block.

**How it is detected/computed:**
- Extract all addresses from transaction inputs
- Extract all addresses from transaction outputs
- Identify intersection — addresses appearing in both sets
- Flag transaction if reuse is detected

**Confidence model:**
- **High:** When the same address appears in input AND output of same transaction
- **Medium:** When reuse occurs across transactions in the same block
- Confidence remains high as address format matching is deterministic

**Limitations:**
- Only detects onchain address reuse within the same transaction/block
- Doesn't track address history across blocks (would require full chain data)
- Some addresses are non-extractable (custom script opcodes, protocols)
- Privacy: address reuse is becoming increasingly rare as wallets implement BIP32 HD key derivation

---

### 4. CoinJoin Detection

**What it detects:**
Identifies CoinJoin-like transactions: transactions with multiple inputs from apparently different owners and equal-value outputs designed to obscure the transaction graph.

**How it is detected/computed:**
- Count frequency of each output value
- If multiple outputs have the same value (e.g., 3+ outputs all 0.5 BTC), flag as CoinJoin-like
- Additionally check:
  - Minimum 3 inputs (single input can't be coinjoin)
  - Symmetric output structure (multiple equal-value outputs)
  - Output value distribution

**Confidence model:**
- **High:** 3+ equal-value outputs AND 3+ inputs
- **Medium:** 2-3 equal-value outputs with multiple inputs
- Can be degraded by: legitimate batches of same amount, dust management patterns
- Only flags when pattern is unambiguous

**Limitations:**
- Many legitimate transactions have equal-value outputs (change management, batch payments)
- True coinjoin detection requires input source analysis (not possible without utxo set)
- Cannot distinguish true CoinJoins from coinswap or other protocols with similar structure
- Doesn't identify coinjoin participants — only flags the pattern
- Privacy protocols like Whirlpool use CoinJoin internally but may blend with other transactions

---

### 5. Consolidation Detection

**What it detects:**
Identifies consolidation transactions where many inputs are combined into 1-2 outputs. These are typical UTXO management operations where wallets reduce fragmentation.

**How it is detected/computed:**
- Count inputs and outputs per transaction
- Flag if: inputs ≥ 3 AND outputs ≤ 2
- Analyze if all outputs share the same script type (indicates consolidation to single wallet)

**Confidence model:**
- **High:** 5+ inputs consolidated to 1-2 outputs of matching script types
- **Medium:** 3-4 inputs to 1-2 outputs with script type matching
- All outputs matching input script type further confirms consolidation intent

**Limitations:**
- Single output consolidations are rarer in modern wallets (usually one change, one payment)
- Some legitimate multi-party transactions have similar structure
- Doesn't confirm that all outputs are self-controlled (just that structure matches consolidation pattern)
- Dust management can create additional outputs, making pattern less clear

---

### 6. Self-Transfer Detection

**What it detects:**
Identifies transactions where all inputs and outputs appear to belong to the same entity — transactions to self (internal transfers, wallet reorganizations).

**How it is detected/computed:**
- Collect all input script types
- Verify all outputs (except OP_RETURN) use one of the input script types
- Flag if input count == output count (perfect forward mapping)
- All outputs must match input type diversity

**Confidence model:**
- **High:** Exact script type match for all in/out pairs + input count == output count
- **Medium:** All outputs match input type set but cardinality differs
- Lower confidence when different script types involved

**Limitations:**
- Many legitimate multi-to-multi transactions (payments to multiple parties with same script type)
- Doesn't prove ownership linkage across addresses (just structural similarity)
- Can't distinguish internal wallet transfers from multi-recipient payments to unrelated parties
- Payjoins (shared input transactions) may be incorrectly flagged

---

### 7. Peeling Chain Detection

**What it detects:**
Detects peeling chain patterns where a large input is split into one small output (payment) and one large output (change), with the large output likely being spent in subsequent transactions following the same pattern.

**How it is detected/computed:**
- Filter transactions with exactly 1 input and 2 outputs
- Calculate ratio of output values: larger / smaller
- If ratio > 2.0, flag as peeling chain candidate
- Report small and large output values for verification

**Confidence model:**
- **High:** 1:2 ratio > 2.5 with clear outlier sizes
- **Medium:** 2.0-2.5 ratio
- Requires output value analysis to confirm (payment vs change pattern)

**Limitations:**
- Doesn't confirm the pattern continues across subsequent transactions (would need chain following)
- Legitimate transactions can have similar structure (e.g., payment + high change)
- Custom ratios may vary; tool uses conservative thresholds
- Can't distinguish peeling chains from legitimate payment structures without multi-tx analysis

---

### 8. OP_RETURN Analysis

**What it detects:**
Identifies OP_RETURN outputs and analyzes embedded data. OP_RETURN outputs are provably unspendable and used for data storage, metadata tagging, and protocol markers.

**How it is detected/computed:**
- Scan all outputs for OP_RETURN script type (begins with 0x6a opcode)
- Count OP_RETURN outputs per transaction
- Attempt protocol identification:
  - **Omni:** Magic bytes 0x6f6d6e69 (four ASCII 'o m n i')
  - **OpenTimestamps:** Magic bytes 0x6f70656e
  - **Generic data:** Other bytestrings
- Track data length for analysis

**Confidence model:**
- **High:** Standard protocol markers identified
- **Medium:** Data length and structure suggest specific protocols
- **Low:** Arbitrary data payloads without clear protocol markers

**Limitations:**
- Can only identify protocols with fixed magic bytes/headers
- Custom protocols escape identification
- Privacy protocols can embed encrypted data indistinguishable from random
- Data extraction doesn't decode/validate protocols (just identifies presence)
- Multi-signature via OP_RETURN not reliably distinguished from true data storage

---

### 9. Round Number Payment Detection

**What it detects:**
Identifies outputs with round-number BTC amounts (e.g., 0.1 BTC, 0.5 BTC, 1.0 BTC), which are more likely to be actual payments than change.

**How it is detected/computed:**
- For each output, convert satoshi value to BTC
- Check if value matches common round amounts: 0.001, 0.01, 0.1, 0.5, 1, 10, 100, etc.
- Flag outputs with round values as likely payments
- Non-round outputs are likely change

**Confidence model:**
- **High:** Exact match to common BTC denominations
- **Medium:** Close to round amounts (within 1% due to rounding)
- Confidence degrades for very large round amounts (1+ BTC) as these can be consolidations

**Limitations:**
- Global adoption of round amounts is not universal; regional/exchange conventions differ
- Legitimate change can accidentally match round numbers
- Some exchanges and services batch payments to specific amounts
- Privacy-conscious actors deliberately avoid round amounts to thwart heuristics
- Doesn't distinguish between intentional payment and coincidental rounding

---

## Architecture

```
sherlock/
├── cmd/
│   ├── cli/main.go              # CLI tool for chain analysis
│   └── web/main.go              # Web server for visualization
├── internal/
│   ├── models/models.go         # Data structures
│   ├── parser/parser.go         # Block/tx parsing from .dat files
│   ├── analysis/analyzer.go     # Heuristic implementations
│   └── output/formatter.go      # JSON/Markdown output generation
├── web/
│   └── ui/                      # Frontend (HTML/JS)
├── go.mod                        # Go module file
├── setup.sh                      # Setup script
├── cli.sh                        # CLI wrapper
├── web.sh                        # Web server wrapper
└── APPROACH.md                   # This file
```

### Data Flow

```
Block Files (.dat)
    ↓
[BlockParser]       — Reads raw bytes, decodes Bitcoin block format
    ↓
[Block/Transaction] — In-memory representation with parsed fields
    ↓
[Analyzer]          — Applies 9 heuristics to each transaction
    ↓
[Formatter]         — Generates JSON + Markdown outputs
    ↓
Output Files (.json, .md) + Web API
```

### Key Components

**BlockParser (internal/parser/parser.go):**
- Reads Bitcoin block files in raw binary format (blk*.dat)
- Decodes block headers: version, prev_hash, merkle_root, timestamp, bits, nonce
- Decodes transactions: inputs, outputs, signatures, witness data
- Calculates block hash via double-SHA256
- Extracts block height from coinbase BIP34 encoding

**Analyzer (internal/analysis/analyzer.go):**
- Applies all 9 heuristics to each transaction
- Maintains transaction index for cross-referencing
- Calculates fee rates (satoshis per virtual byte)
- Classifies transactions based on heuristic results

**Formatter (internal/output/formatter.go):**
- Builds JSON output matching required schema
- Generates human-readable Markdown reports
- Aggregates statistics across blocks within a file
- Groups transactions by classification

**Web Server (cmd/web/main.go):**
- Serves JSON API for block analysis results
- Provides REST endpoints: /api/blocks, /api/block/{name}, /api/health
- Serves static HTML/JS frontend for interactive exploration

---

## Trade-Offs and Design Decisions

### 1. Accuracy vs. Performance

**Decision:** Prioritized heuristic applicability over computational optimization.

**Rationale:**
- Block files contain thousands of transactions; O(n²) analysis would be prohibitive
- Implemented O(n) per-heuristic analysis instead
- Each heuristic operates independently; can be parallelized in future
- Accepted some false positives (e.g., legitimate transactions flagged by CIOH) in exchange for simplicity and correctness

### 2. Script Type Classification

**Decision:** Implemented fixed script type detection via byte pattern matching rather than relying on external libraries.

**Rationale:**
- Need to classify P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN
- btcd library available but added complexity
- Pattern matching is fast, verifiable, and works offline
- Trade-off: less robust to edge cases; acceptable for standard Bitcoin scripts

### 3. Fee Rate Calculation

**Decision:** Simplified fee rate calculation using transaction count as proxy for vbytes.

**Rationale:**
- Accurate vbyte calculation requires knowing input/output script types
- Current implementation: fee_rate = fee / transaction_size_bytes_estimate
- Sufficient for statistical analysis
- Future: refine with witness discount calculation (3x bytes for witness, 4x for non-witness)

### 4. Change Detection Priority

**Decision:** Implemented script type matching first; round number analysis as secondary strategy.

**Rationale:**
- Script type matching has higher accuracy for most wallets
- Round number detection useful but creates false positives
- Multi-strategy approach allows fallback when primary fails
- Order matters: strict matching reduces noise

### 5. Heuristic Independence

**Decision:** Each heuristic operates independently on transaction data.

**Rationale:**
- Simplifies debugging and testing
- Allows heuristic results to be interpreted separately
- Reduces coupling between analysis components
- Trade-off: could implement correlation detection across heuristics (e.g., CoinJoin + Address Reuse)

### 6. JSON vs Markdown Output

**Decision:** JSON for machine readability; Markdown for human exploration.

**Rationale:**
- JSON enables automated grading, API consumption, and integration
- Markdown provides git-friendly, diffs-friendly format for version control
- Both outputs derived from same analysis; no duplication
- Markdown includes narrative context (what each heuristic means)

### 7. Web UI Technology

**Decision:** Plain HTML/CSS/JavaScript without frameworks; pure static + API approach.

**Rationale:**
- No build step required; simple deployment
- Minimal dependencies; works in any environment
- API-first design separates data (backend) from presentation (frontend)
- Trade-off: less interactive features; sufficient for requirements

---

## References

### BIPs (Bitcoin Improvement Proposals)

- **BIP 32:** Hierarchical Deterministic Wallets — defines key derivation, explains address generation and change output handling
- **BIP 34:** Block Height in Coinbase — used to extract block height from coinbase transaction
- **BIP 141:** Segregated Witness (Consensus Layer) — defines P2WPKH, P2WSH scripts and witness data
- **BIP 141/BIP 144:** Transaction Witness Encoding — witness data format and vbyte discounting
- **BIP 173:** Base32 Encoding of Witness Programs (Bech32) — witness address format, script validation

### Chain Analysis & Privacy Papers

- **Meiklejohn et al. (2013):** "A Fistful of Bitcoins: Characterizing Payments Among Men with No Names" — foundational work on UTXO clustering via CIOH
- **Androulaki et al. (2013):** Bitcoin over Tor isn't a good idea (IEEE S&P 2013) — transaction graph analysis techniques
- **Ermilov et al. (2018):** "Fast Money Grows on Trees" — Bitcoin address clustering and entity identification

### Heuristic Catalogues & Tools

- **Chainalysis:** CoinJoin detection heuristics; peer input linking; behavioral classification
- **Elliptic:** Transaction purpose classification; risk scoring methodologies
- **Bitcoin Core Documentation:** Transaction serialization format; script opcodes; validation rules

### Additional Resources

- **Bitcoin Developer Reference:** Block and transaction structure
- **btcd Full Node Implementation:** Go bitcoin implementation; reference for validation logic
- **Chain Analysis Limitations:** Privacy-By-Design improvements (CoinJoin, Taproot, sidechains)

---

## Known Limitations & Future Work

### Current Limitations

1. **No UTXO Set Access:**
   - Cannot verify input ownership without full chain
   - Change detection relies on heuristics and patterns, not confirmability
   - Cross-transaction linking limited to within-block scope

2. **No Signature Validation:**
   - Cannot verify that claimed inputs actually belong to the signing key
   - No script execution or sighash commitment verification
   - Assumes transaction is valid (grader responsibility)

3. **Privacy Protocol Blindness:**
   - CoinJoin transactions are detectable by structure but participants not identified
   - Taproot transactions hide script type; only distinguished by size heuristics
   - Cross-chain protocols (atomic swaps, sidechains) not identifi

4. **Single-Block Scope:**
   - Heuristics don't correlate transactions across blocks (peeling chains not fully traced)
   - Address reuse detection limited to within-block matches
   - No temporal analysis or clustering across time

### Future Enhancements

1. **Multi-Block Analysis:**
   - Extend peeling chain detection across transaction history
   - Build entity clusters across multiple blocks
   - Temporal pattern analysis (same wallet, recurring behavior)

2. **Advanced Script Analysis:**
   - Implement multisig detection and analysis
   - Timelock and CSV pattern recognition
   - Custom opcode sequence detection

3. **Protocol Integration:**
   - Omni, Counterparty, and other colored coin protocol parsing
   - Stablecoin and token transfer tracking
   - NFT/Inscription data analysis

4. **Confidence Scoring:**
   - Probabilistic model (Bayesian) rather than categorical
   - Machine learning for pattern recognition
   - User feedback incorporation for retraining

5. **Performance Optimization:**
   - Parallel heuristic application
   - GPU-accelerated hash calculations
   - Database indexing for large-scale analysis

---

## Testing & Validation

The analyzer is tested against provided Bitcoin block fixtures containing real block data. Validation checks

 ensure:

- JSON schema compliance (all required fields present with correct types)
- Heuristic application consistency (same inputs produce same results)
- Aggregation correctness (per-block + per-file summaries align)
- Output reproducibility (re-running produces identical results)

---

**Document Version:** 1.0  
**Last Updated:** 2026-03-12  
**Language:** Go 1.21+  

<!-- Known false positives/negatives, edge cases -->

---

### 2. Change Detection

**What it detects:**
<!-- Explain what the heuristic identifies -->

**How it is detected/computed:**
<!-- Describe your algorithm or logic -->

**Confidence model:**
<!-- How do you score or rank confidence? -->

**Limitations:**
<!-- Known false positives/negatives, edge cases -->

---

### 3. (Your next heuristic)

**What it detects:**

**How it is detected/computed:**

**Confidence model:**

**Limitations:**

---

<!-- Repeat the section above for each additional heuristic you implement.
     You must implement at least 5 heuristics total, including CIOH and Change Detection. -->

---

## Architecture Overview

<!-- Describe the overall structure of your solution: what languages/frameworks you used, how the code is organized, how data flows from raw block files to JSON + Markdown output. -->

---

## Trade-offs and Design Decisions

<!-- Describe any important trade-offs you made (e.g., accuracy vs performance, simplicity vs coverage). Explain why you chose the heuristics you did and how you handle ambiguous cases. -->

---

## References

<!-- List any references you used: BIPs, papers, blog posts, documentation, etc. -->
