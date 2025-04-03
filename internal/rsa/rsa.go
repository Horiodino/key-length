package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Horiodino/key-length/internal/types"
)

type RSAKey struct {
	data      []byte
	cert      *x509.Certificate
	rsaPub    *rsa.PublicKey
	rsaPriv   *rsa.PrivateKey
	isPrivate bool
}

func NewRSAKey(data []byte) (*RSAKey, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	r := &RSAKey{data: data}

	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "RSA PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse PEM RSA public key: " + err.Error())
			}
			switch pub := pub.(type) {
			case *rsa.PublicKey:
				r.rsaPub = pub
				return r, nil
			default:
				return nil, errors.New("parsed PEM public key is not RSA")
			}
		case "RSA PRIVATE KEY":
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse PEM RSA private key: " + err.Error())
			}
			r.rsaPriv = priv
			r.rsaPub = &priv.PublicKey
			r.isPrivate = true
			return r, nil
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse PEM certificate: " + err.Error())
			}
			if cert.PublicKeyAlgorithm == x509.RSA {
				r.cert = cert
				return r, nil
			}
			return nil, errors.New("certificate does not contain RSA key")
		default:
			return nil, errors.New("unsupported PEM block type: " + block.Type)
		}
	}

	cert, err := x509.ParseCertificate(data)
	if err == nil && cert.PublicKeyAlgorithm == x509.RSA {
		r.cert = cert
		return r, nil
	}

	return nil, errors.New("unsupported RSA key format: expected PEM or X.509 DER")
}

func (r *RSAKey) GetLength() int {
	if r.cert != nil {
		if rsaPub, ok := r.cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub.N.BitLen()
		}
	}

	if r.rsaPub != nil {
		return r.rsaPub.N.BitLen()
	}

	if r.rsaPriv != nil {
		return r.rsaPriv.N.BitLen()
	}

	return 0
}

// TODO Better Implementation
func (r *RSAKey) IsSecure(threshold int) bool {
	length := r.GetLength()
	return length >= threshold
}

func (r *RSAKey) AdjustForYear(year int) int {
	baseThreshold := 2048
	yearsSince2020 := year - 2020
	if yearsSince2020 <= 0 {
		return baseThreshold
	}

	additionalBits := (yearsSince2020 / 5) * 128
	return baseThreshold + additionalBits
}

func (r *RSAKey) GetAlgorithm() string {
	return "RSA"
}

var _ types.KeyLengthEvaluator = (*RSAKey)(nil)
