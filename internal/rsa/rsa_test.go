package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"testing"
	"time"
)

func TestNewRSAKey(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewRSAKey(nil)
		if err == nil {
			t.Errorf("Expected error when data is nil")
		}
	})

	t.Run("InvalidData", func(t *testing.T) {
		_, err := NewRSAKey([]byte("invalid data"))
		if err == nil {
			t.Errorf("Expected error with invalid data")
		}
	})

	t.Run("ValidX509CertificatePEM", func(t *testing.T) {
		cert := generateTestCertificate(t, 2048, true)
		key, err := NewRSAKey(cert)
		if err != nil {
			t.Errorf("Failed to create RSAKey from valid PEM certificate: %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil RSAKey")
		}
	})

	t.Run("ValidX509CertificateDER", func(t *testing.T) {
		cert := generateTestCertificate(t, 2048, false)
		key, err := NewRSAKey(cert)
		if err != nil {
			t.Errorf("Failed to create RSAKey from valid DER certificate: %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil RSAKey")
		}
	})

	t.Run("PEMRSAPublicKey", func(t *testing.T) {
		pemKey := generateRSAPEMPublicKey(t, 2048)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Errorf("Failed to create RSAKey from PEM RSA PUBLIC KEY: %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil RSAKey")
		}
	})

	t.Run("PEMRSAPrivateKey", func(t *testing.T) {
		pemKey := generateRSAPEMPrivateKey(t, 2048)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Errorf("Failed to create RSAKey from PEM RSA PRIVATE KEY: %v", err)
		}
		if key == nil {
			t.Errorf("Expected non-nil RSAKey")
		} else if !key.isPrivate {
			t.Errorf("Expected key to be marked as private")
		}
	})

	t.Run("PEMRSAPrivateKey2048", func(t *testing.T) {
		pemKey := generateRSAPEMPrivateKey(t, 2048)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Fatalf("Failed to create RSAKey from private PEM: %v", err)
		}
		length := key.GetLength()
		if length != 2048 {
			t.Errorf("Expected length 2048, got %d", length)
		}
	})

	t.Run("PEMRSAPrivateKey4096", func(t *testing.T) {
		pemKey := generateRSAPEMPrivateKey(t, 4096)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Fatalf("Failed to create RSAKey from private PEM: %v", err)
		}
		length := key.GetLength()
		if length != 4096 {
			t.Errorf("Expected length 4096, got %d", length)
		}
	})
}

func TestGetLength(t *testing.T) {
	t.Run("X509CertificatePEM2048", func(t *testing.T) {
		cert := generateTestCertificate(t, 2048, true)
		key, err := NewRSAKey(cert)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 2048 {
			t.Errorf("Expected length 2048, got %d", length)
		}
	})

	t.Run("X509CertificateDER2048", func(t *testing.T) {
		cert := generateTestCertificate(t, 2048, false)
		key, err := NewRSAKey(cert)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 2048 {
			t.Errorf("Expected length 2048, got %d", length)
		}
	})

	t.Run("X509CertificatePEM4096", func(t *testing.T) {
		cert := generateTestCertificate(t, 4096, true)
		key, err := NewRSAKey(cert)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 4096 {
			t.Errorf("Expected length 4096, got %d", length)
		}
	})

	t.Run("X509CertificateDER4096", func(t *testing.T) {
		cert := generateTestCertificate(t, 4096, false)
		key, err := NewRSAKey(cert)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 4096 {
			t.Errorf("Expected length 4096, got %d", length)
		}
	})

	t.Run("PEMRSAPublicKey2048", func(t *testing.T) {
		pemKey := generateRSAPEMPublicKey(t, 2048)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 2048 {
			t.Errorf("Expected length 2048, got %d", length)
		}
	})

	t.Run("PEMRSAPublicKey4096", func(t *testing.T) {
		pemKey := generateRSAPEMPublicKey(t, 4096)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 4096 {
			t.Errorf("Expected length 4096, got %d", length)
		}
	})

	t.Run("PEMRSAPrivateKey2048", func(t *testing.T) {
		pemKey := generateRSAPEMPrivateKey(t, 2048)
		key, err := NewRSAKey(pemKey)
		if err != nil {
			t.Fatalf("Failed to create RSAKey: %v", err)
		}
		length := key.GetLength()
		if length != 2048 {
			t.Errorf("Expected length 2048, got %d", length)
		}
	})
}

func TestIsSecure(t *testing.T) {
	testCases := []struct {
		keySize   int
		threshold int
		expected  bool
	}{
		{2048, 2048, true},
		{2048, 3072, false},
		{4096, 2048, true},
		{4096, 4096, true},
		{3072, 4096, false},
	}
	for _, tc := range testCases {
		t.Run("KeySize_"+strconv.Itoa(tc.keySize)+"_Threshold_"+strconv.Itoa(tc.threshold), func(t *testing.T) {
			cert := generateTestCertificate(t, tc.keySize, true)
			key, err := NewRSAKey(cert)
			if err != nil {
				t.Fatalf("Failed to create RSAKey: %v", err)
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
		{2025, 2048},
		{2030, 2048},
		{2031, 3072},
		{2050, 3072},
		{2051, 4096},
		{2100, 4096},
	}

	cert := generateTestCertificate(t, 2048, true)
	key, err := NewRSAKey(cert)
	if err != nil {
		t.Fatalf("Failed to create RSAKey: %v", err)
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

func generateTestCertificate(t *testing.T, bits int, asPEM bool) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test RSA Cert"},
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

func generateRSAPEMPublicKey(t *testing.T, bits int) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	return pem.EncodeToMemory(pemBlock)
}

func generateRSAPEMPrivateKey(t *testing.T, bits int) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return pem.EncodeToMemory(pemBlock)
}
