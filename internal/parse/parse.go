package parse

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/Horiodino/key-length/internal/ecc"
	"github.com/Horiodino/key-length/internal/rsa"
)

type ParsedKey struct {
	Key interface{}
}

func ParseFile(filename string) (*ParsedKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("failed to read file: " + err.Error())
	}
	return ParseData(data)
}

func ParseData(data []byte) (*ParsedKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "RSA PUBLIC KEY", "RSA PRIVATE KEY":
			key, err := rsa.NewRSAKey(data)
			if err != nil {
				return nil, err
			}
			return &ParsedKey{Key: key}, nil
		case "EC PUBLIC KEY":
			key, err := ecc.NewECCKey(data)
			if err != nil {
				return nil, err
			}
			return &ParsedKey{Key: key}, nil
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse PEM certificate: " + err.Error())
			}
			switch cert.PublicKeyAlgorithm {
			case x509.RSA:
				key, err := rsa.NewRSAKey(data)
				if err != nil {
					return nil, err
				}
				return &ParsedKey{Key: key}, nil
			case x509.ECDSA:
				key, err := ecc.NewECCKey(data)
				if err != nil {
					return nil, err
				}
				return &ParsedKey{Key: key}, nil
			default:
				return nil, errors.New("unsupported key algorithm in certificate: " + cert.PublicKeyAlgorithm.String())
			}
		default:
			return nil, errors.New("unsupported PEM block type: " + block.Type)
		}
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, errors.New("failed to parse DER certificate: " + err.Error())
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		key, err := rsa.NewRSAKey(data)
		if err != nil {
			return nil, err
		}
		return &ParsedKey{Key: key}, nil
	case x509.ECDSA:
		key, err := ecc.NewECCKey(data)
		if err != nil {
			return nil, err
		}
		return &ParsedKey{Key: key}, nil
	default:
		return nil, errors.New("unsupported key algorithm in certificate: " + cert.PublicKeyAlgorithm.String())
	}
}
