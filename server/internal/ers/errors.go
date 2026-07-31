package ers

import (
	"crypto"
	"errors"
	"fmt"
)

// ErrEmpty is returned when a generation request carries no data objects.
var ErrEmpty = errors.New("ers: at least one protected data object is required")

// ErrNoTimestamp is returned when an ArchiveTimeStamp carries no timestamp
// token, or an EvidenceRecord carries no ArchiveTimeStamp.
var ErrNoTimestamp = errors.New("ers: evidence record contains no archive timestamp")

// UnsupportedHashError reports a hash algorithm outside the SHA-2 family this
// package implements.
type UnsupportedHashError struct{ Hash crypto.Hash }

func (e *UnsupportedHashError) Error() string {
	return fmt.Sprintf("ers: unsupported hash algorithm %v (SHA-256/384/512 only)", e.Hash)
}

// VerifyError reports a failed EvidenceRecord verification, identifying the
// data object (when applicable), the chain index, and the underlying reason.
type VerifyError struct {
	// ObjectID identifies the protected data object whose inclusion could not be
	// proven; empty for a structural or timestamp failure.
	ObjectID string
	// Chain is the zero-based ArchiveTimeStampChain index the failure occurred
	// in; -1 for a whole-record failure.
	Chain int
	// Reason is the human-readable cause.
	Reason string
	// Err is the wrapped underlying error, if any.
	Err error
}

func (e *VerifyError) Error() string {
	loc := ""
	if e.Chain >= 0 {
		loc = fmt.Sprintf(" (chain %d)", e.Chain)
	}
	obj := ""
	if e.ObjectID != "" {
		obj = fmt.Sprintf(" for object %q", e.ObjectID)
	}
	if e.Err != nil {
		return fmt.Sprintf("ers: verification failed%s%s: %s: %v", obj, loc, e.Reason, e.Err)
	}
	return fmt.Sprintf("ers: verification failed%s%s: %s", obj, loc, e.Reason)
}

func (e *VerifyError) Unwrap() error { return e.Err }

func verifyErr(chain int, objectID, reason string, err error) *VerifyError {
	return &VerifyError{ObjectID: objectID, Chain: chain, Reason: reason, Err: err}
}
