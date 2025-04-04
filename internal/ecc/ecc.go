package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Horiodino/key-length/internal/types"
)

type ECCKey struct {
	data     []byte
	cert     *x509.Certificate
	ecdsaPub *ecdsa.PublicKey
}

func NewECCKey(data []byte) (*ECCKey, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	e := &ECCKey{data: data}

	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "EC PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse PEM EC public key: " + err.Error())
			}
			if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
				e.ecdsaPub = ecdsaPub
				return e, nil
			}
			return nil, errors.New("parsed PEM public key is not ECDSA")
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse PEM certificate: " + err.Error())
			}
			if cert.PublicKeyAlgorithm == x509.ECDSA {
				e.cert = cert
				return e, nil
			}
			return nil, errors.New("certificate does not contain ECDSA key")
		default:
			return nil, errors.New("unsupported PEM block type: " + block.Type)
		}
	}

	cert, err := x509.ParseCertificate(data)
	if err == nil && cert.PublicKeyAlgorithm == x509.ECDSA {
		e.cert = cert
		return e, nil
	}

	return nil, errors.New("unsupported ECC key format: expected PEM or X.509 DER")
}

func (e *ECCKey) GetLength() int {
	var curve elliptic.Curve
	if e.cert != nil {
		if ecdsaPub, ok := e.cert.PublicKey.(*ecdsa.PublicKey); ok {
			curve = ecdsaPub.Curve
		}
	} else if e.ecdsaPub != nil {
		curve = e.ecdsaPub.Curve
	}

	if curve == nil {
		return 0
	}

	return curve.Params().BitSize
}

func (e *ECCKey) IsSecure(threshold int) bool {
	length := e.GetLength()
	return length >= threshold
}

func (e *ECCKey) AdjustForYear(year int) int {
	switch {
	case year <= 2030:
		return 256
	case year <= 2040:
		return 384
	default:
		return 521
	}
}

func (e *ECCKey) GetAlgorithm() string {
	return "ECC"
}

var _ types.KeyLengthEvaluator = (*ECCKey)(nil)
