package symmetric

import (
	"github.com/Horiodino/key-length/internal/types"
)

type SymmetricKey struct {
	length int
}

func NewSymmetricKey(length int) *SymmetricKey {
	return &SymmetricKey{length: length}
}

func (s *SymmetricKey) GetLength() int {
	return s.length
}

func (s *SymmetricKey) IsSecure(threshold int) bool {
	return s.length >= threshold
}

func (s *SymmetricKey) AdjustForYear(year int) int {
	baseLength := 128
	yearsDiff := year - 2025
	if yearsDiff <= 0 {
		return baseLength
	}
	adjusted := float64(baseLength) + float64(yearsDiff)*0.67
	return int(adjusted)
}

func (s *SymmetricKey) GetAlgorithm() string {
	return "Symmetric"
}

var _ types.KeyLengthEvaluator = (*SymmetricKey)(nil)
