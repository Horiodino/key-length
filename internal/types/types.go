package types

type KeyLengthEvaluator interface {
	GetLength() int
	GetAlgorithm() string
	IsSecure(threshold int) bool
	AdjustForYear(year int) int
}
