package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"testing"
	"time"
)

func TestNewECCKey(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewECCKey(nil)
		if err == nil {
			t.Errorf("Expected error when data is nil")
		}
	})

	t.Run("InvalidData", func(t *testing.T) {
		_, err := NewECCKey([]byte("invalid data"))
		if err == nil {
			t.Errorf("Expected error with invalid data")
		}
	})

	t.Run("ValidX509CertificatePEMP256", func(t *testing.T) {
		cert := generateTestCertificate(t, elliptic.P256(), true)
		key, err := NewECCKey(cert)
		if err != nil {
			t.Errorf("Failed to create ECCKey from valid PEM certificate (P-256): %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil ECCKey")
		}
	})

	t.Run("ValidX509CertificateDERP256", func(t *testing.T) {
		cert := generateTestCertificate(t, elliptic.P256(), false)
		key, err := NewECCKey(cert)
		if err != nil {
			t.Errorf("Failed to create ECCKey from valid DER certificate (P-256): %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil ECCKey")
		}
	})

	t.Run("ValidX509CertificatePEMP384", func(t *testing.T) {
		cert := generateTestCertificate(t, elliptic.P384(), true)
		key, err := NewECCKey(cert)
		if err != nil {
			t.Errorf("Failed to create ECCKey from valid PEM certificate (P-384): %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil ECCKey")
		}
	})

	t.Run("ValidX509CertificateDERP521", func(t *testing.T) {
		cert := generateTestCertificate(t, elliptic.P521(), false)
		key, err := NewECCKey(cert)
		if err != nil {
			t.Errorf("Failed to create ECCKey from valid DER certificate (P-521): %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil ECCKey")
		}
	})

	t.Run("PEMECPublicKeyP256", func(t *testing.T) {
		pemKey := generateECPEMPublicKey(t, elliptic.P256())
		key, err := NewECCKey(pemKey)
		if err != nil {
			t.Errorf("Failed to create ECCKey from PEM EC PUBLIC KEY (P-256): %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil ECCKey")
		}
	})

	t.Run("PEMECPublicKeyP384", func(t *testing.T) {
		pemKey := generateECPEMPublicKey(t, elliptic.P384())
		key, err := NewECCKey(pemKey)
		if err != nil {
			t.Errorf("Failed to create ECCKey from PEM EC PUBLIC KEY (P-384): %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil ECCKey")
		}
	})
}

func TestGetLength(t *testing.T) {
	testCases := []struct {
		curve    elliptic.Curve
		expected int
	}{
		{elliptic.P256(), 256},
		{elliptic.P384(), 384},
		{elliptic.P521(), 521},
	}

	for _, tc := range testCases {
		t.Run("X509CertificatePEMPublicKey"+strconv.Itoa(tc.expected), func(t *testing.T) {
			cert := generateTestCertificate(t, tc.curve, true)
			key, err := NewECCKey(cert)
			if err != nil {
				t.Fatalf("Failed to create ECCKey: %v", err)
			}
			length := key.GetLength()
			if length != tc.expected {
				t.Errorf("Expected length %d for %s, got %d", tc.expected, tc.curve.Params().Name, length)
			}
		})

		t.Run("X509CertificateDERPublicKey"+strconv.Itoa(tc.expected), func(t *testing.T) {
			cert := generateTestCertificate(t, tc.curve, false)
			key, err := NewECCKey(cert)
			if err != nil {
				t.Fatalf("Failed to create ECCKey: %v", err)
			}
			length := key.GetLength()
			if length != tc.expected {
				t.Errorf("Expected length %d for %s, got %d", tc.expected, tc.curve.Params().Name, length)
			}
		})

		t.Run("PEMECPublicKey"+strconv.Itoa(tc.expected), func(t *testing.T) {
			pemKey := generateECPEMPublicKey(t, tc.curve)
			key, err := NewECCKey(pemKey)
			if err != nil {
				t.Fatalf("Failed to create ECCKey: %v", err)
			}
			length := key.GetLength()
			if length != tc.expected {
				t.Errorf("Expected length %d for %s, got %d", tc.expected, tc.curve.Params().Name, length)
			}
		})
	}
}

func TestIsSecure(t *testing.T) {
	testCases := []struct {
		keySize   int
		threshold int
		expected  bool
	}{
		{256, 256, true},
		{256, 384, false},
		{384, 256, true},
		{384, 384, true},
		{521, 384, true},
		{521, 521, true},
	}

	for _, tc := range testCases {
		var curve elliptic.Curve
		switch tc.keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		t.Run("KeySize_"+strconv.Itoa(tc.keySize)+"_Threshold_"+strconv.Itoa(tc.threshold), func(t *testing.T) {
			cert := generateTestCertificate(t, curve, true)
			key, err := NewECCKey(cert)
			if err != nil {
				t.Fatalf("Failed to create ECCKey: %v", err)
			}
			if key.IsSecure(tc.threshold) != tc.expected {
				t.Errorf("Expected IsSecure(%d) to be %v for key size %d",
					tc.threshold, tc.expected, tc.keySize)
			}
		})
	}
}

func TestAdjustForYear(t *testing.T) {
	testCases := []struct {
		year     int
		expected int
	}{
		{2025, 256},
		{2030, 256},
		{2031, 384},
		{2040, 384},
		{2041, 521},
		{2100, 521},
	}

	cert := generateTestCertificate(t, elliptic.P256(), true)
	key, err := NewECCKey(cert)
	if err != nil {
		t.Fatalf("Failed to create ECCKey: %v", err)
	}
	for _, tc := range testCases {
		t.Run("Year_"+strconv.Itoa(tc.year), func(t *testing.T) {
			recommended := key.AdjustForYear(tc.year)
			if recommended != tc.expected {
				t.Errorf("For year %d, expected recommendation %d, got %d",
					tc.year, tc.expected, recommended)
			}
		})
	}
}

func generateTestCertificate(t *testing.T, curve elliptic.Curve, asPEM bool) []byte {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test ECC Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	if !asPEM {
		return certDER
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return pem.EncodeToMemory(pemBlock)
}

func generateECPEMPublicKey(t *testing.T, curve elliptic.Curve) []byte {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	return pem.EncodeToMemory(pemBlock)
}
