package eval

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Horiodino/key-length/internal/config"
	"github.com/Horiodino/key-length/internal/ecc"
	"github.com/Horiodino/key-length/internal/rsa"
	"github.com/Horiodino/key-length/internal/types"
)

type EvaluationResult struct {
	Algorithm     string
	Length        int
	Status        string
	Expiry        string
	ExpiryWarning string
}

func EvaluateKey(key types.KeyLengthEvaluator, cfg *config.Config, certData []byte) *EvaluationResult {
	length := key.GetLength()
	var algorithm string

	switch key.(type) {
	case *rsa.RSAKey:
		algorithm = "RSA"
	case *ecc.ECCKey:
		algorithm = "ECC"
	default:
		algorithm = "Unknown"
	}

	threshold := cfg.GetThreshold(algorithm)
	isSecure := length >= threshold

	expiry := "N/A"
	expiryWarning := ""

	if certData != nil {
		cert, err := x509.ParseCertificate(certData)
		if err == nil {
			expiry = cert.NotAfter.Format("2006-01-02")
			threshold := 90 * 24 * time.Hour
			if time.Until(cert.NotAfter) < threshold {
				daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
				expiryWarning = fmt.Sprintf("Warning: Certificate expires in %d days (threshold: 90 days)", daysLeft)
			}
		}
	}

	return &EvaluationResult{
		Algorithm: algorithm,
		Length:    length,
		Status: fmt.Sprintf("%s (%s)", func() string {
			if isSecure {
				return "Secure"
			}
			return "Insecure"
		}(), cfg.SelectedStandard),
		Expiry:        expiry,
		ExpiryWarning: expiryWarning,
	}
}
