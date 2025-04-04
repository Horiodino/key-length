package eval

import (
	"fmt"

	"github.com/Horiodino/key-length/internal/config"
	"github.com/Horiodino/key-length/internal/types"
)

type EvaluationResult struct {
	Algorithm string
	Length    int
	Status    string
}

func EvaluateKey(key types.KeyLengthEvaluator, cfg *config.Config) *EvaluationResult {
	algorithm, length := key.GetAlgorithm(), key.GetLength()
	threshold := cfg.GetThreshold(algorithm)
	isSecure := length >= threshold
	return &EvaluationResult{
		Algorithm: algorithm,
		Length:    length,
		Status: fmt.Sprintf("%s (%s)", func() string {
			if isSecure {
				return "Secure"
			}
			return "Insecure"
		}(), cfg.SelectedStandard),
	}
}
