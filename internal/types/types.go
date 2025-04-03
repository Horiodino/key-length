package types

// KeyLengthEvaluator defines the interface for evaluating key lengths.
type KeyLengthEvaluator interface {
	// GetLength returns the key length in bits.
	GetLength() int
	// IsSecure checks if the key length meets a given threshold or predefined standard.
	IsSecure(threshold int) bool
	// AdjustForYear calculates the adjusted minimum length for a future year.
	AdjustForYear(year int) int
}
