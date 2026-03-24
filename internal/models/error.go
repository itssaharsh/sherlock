// Package models defines JSON output schema for Chain Lens error handling.
package models

import "fmt"

// ErrorResult is the JSON output for error conditions.
type ErrorResult struct {
	OK    bool       `json:"ok"`
	Error ErrorInfo `json:"error"`
}

// ErrorInfo contains the error details.
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewErrorResult creates a new error result with the given code and message.
func NewErrorResult(code, message string) ErrorResult {
	return ErrorResult{
		OK: false,
		Error: ErrorInfo{
			Code:    code,
			Message: message,
		},
	}
}

// NewErrorResultf creates a new error result with formatted message.
func NewErrorResultf(code, format string, args ...interface{}) ErrorResult {
	return NewErrorResult(code, fmt.Sprintf(format, args...))
}

// Error codes for various failure conditions.
const (
	// Transaction parsing errors
	ErrCodeInvalidTx          = "INVALID_TX"
	ErrCodeMalformedTx        = "MALFORMED_TX"
	ErrCodeInvalidHex         = "INVALID_HEX"
	ErrCodeTruncatedTx        = "TRUNCATED_TX"
	ErrCodeInvalidWitness     = "INVALID_WITNESS"
	
	// Prevout errors
	ErrCodeMissingPrevout     = "MISSING_PREVOUT"
	ErrCodeDuplicatePrevout   = "DUPLICATE_PREVOUT"
	ErrCodeExtraPrevout       = "EXTRA_PREVOUT"
	ErrCodeInvalidPrevout     = "INVALID_PREVOUT"
	
	// Fixture errors
	ErrCodeInvalidFixture     = "INVALID_FIXTURE"
	ErrCodeInvalidJSON        = "INVALID_JSON"
	ErrCodeMissingField       = "MISSING_FIELD"
	
	// Block errors
	ErrCodeInvalidBlockHeader = "INVALID_BLOCK_HEADER"
	ErrCodeMerkleRootMismatch = "MERKLE_ROOT_MISMATCH"
	ErrCodeInvalidCoinbase    = "INVALID_COINBASE"
	ErrCodeInvalidUndoData    = "INVALID_UNDO_DATA"
	ErrCodeTruncatedUndo      = "TRUNCATED_UNDO"
	ErrCodeUndoMismatch       = "UNDO_MISMATCH"
	
	// File I/O errors
	ErrCodeFileNotFound       = "FILE_NOT_FOUND"
	ErrCodeFileReadError      = "FILE_READ_ERROR"
	ErrCodeInvalidXORKey      = "INVALID_XOR_KEY"
	
	// Script errors
	ErrCodeInvalidScript      = "INVALID_SCRIPT"
	ErrCodeScriptTooLong      = "SCRIPT_TOO_LONG"
)

// AnalysisError is a custom error type that carries an error code.
type AnalysisError struct {
	Code    string
	Message string
	Cause   error
}

func (e *AnalysisError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AnalysisError) Unwrap() error {
	return e.Cause
}

// NewAnalysisError creates a new analysis error.
func NewAnalysisError(code, message string, cause error) *AnalysisError {
	return &AnalysisError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// NewAnalysisErrorf creates a new analysis error with formatted message.
func NewAnalysisErrorf(code string, format string, args ...interface{}) *AnalysisError {
	return &AnalysisError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// ToErrorResult converts an AnalysisError to an ErrorResult.
func (e *AnalysisError) ToErrorResult() ErrorResult {
	return NewErrorResult(e.Code, e.Message)
}
