package client

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

type ecdsaSigner struct {
	privateKey *btcec.PrivateKey
}

func NewECDSASigner(key *btcec.PrivateKey) *ecdsaSigner {
	return &ecdsaSigner{privateKey: key}
}

// OIDs used in PKCS#8 for EC keys
var (
	oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs8PrivateKey struct {
	Version    int
	Algo       algorithmIdentifier
	PrivateKey []byte
}

type sec1ECPrivateKey struct {
	Version    int
	PrivateKey []byte
	// We don't need Parameters/PublicKey for deriving the private scalar.
	Parameters asn1.RawValue  `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
}

func newECDSASignerFromHexKey(hexKey string) (*ecdsaSigner, error) {
	decodedHexKey, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}

	priv, _ := btcec.PrivKeyFromBytes(decodedHexKey)
	if priv == nil {
		return nil, errors.New("private key is nil")
	}

	return &ecdsaSigner{privateKey: priv}, nil
}

func newECDSASignerFromPem(pemString string) (*ecdsaSigner, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}

	var d32 []byte
	switch block.Type {
	case "EC PRIVATE KEY":
		// Parse SEC1 ECPrivateKey without involving x509 curve registry
		var sec1 sec1ECPrivateKey
		if _, err := asn1.Unmarshal(block.Bytes, &sec1); err != nil {
			return nil, err
		}
		if len(sec1.PrivateKey) == 0 {
			return nil, errors.New("empty EC private key")
		}
		// Left-pad to 32 bytes
		d32 = make([]byte, 32)
		copy(d32[32-len(sec1.PrivateKey):], sec1.PrivateKey)
	case "PRIVATE KEY":
		// PKCS#8 wrapper; avoid x509.ParsePKCS8PrivateKey to support secp256k1
		var p8 pkcs8PrivateKey
		if _, err := asn1.Unmarshal(block.Bytes, &p8); err != nil {
			return nil, err
		}
		// Optionally validate algorithm is id-ecPublicKey
		if !p8.Algo.Algorithm.Equal(oidEcPublicKey) {
			return nil, errors.New("unsupported PKCS#8 algorithm: " + p8.Algo.Algorithm.String())
		}
		// If parameters present and are OID, we can check for secp256k1 but it's optional for extracting d
		// The privateKey field itself holds a DER-encoded ECPrivateKey (SEC1)
		var sec1 sec1ECPrivateKey
		if _, err := asn1.Unmarshal(p8.PrivateKey, &sec1); err != nil {
			return nil, err
		}
		if len(sec1.PrivateKey) == 0 {
			return nil, errors.New("empty EC private key in PKCS#8")
		}
		d32 = make([]byte, 32)
		copy(d32[32-len(sec1.PrivateKey):], sec1.PrivateKey)
	case "EC RAW PRIVATE KEY":
		// Accept raw 32-byte scalar in PEM for tests/compat
		if len(block.Bytes) == 0 || len(block.Bytes) > 32 {
			return nil, errors.New("invalid raw EC private key size")
		}
		d32 = make([]byte, 32)
		copy(d32[32-len(block.Bytes):], block.Bytes)
	default:
		return nil, errors.New("unsupported PEM type: " + block.Type)
	}

	priv, pub := btcec.PrivKeyFromBytes(d32)
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	// print private key in hex
	fmt.Printf("private key hex: %s\n", hex.EncodeToString(d32))
	fmt.Printf("public key hex (uncompressed): %s\n", hex.EncodeToString(pub.SerializeUncompressed()))
	fmt.Printf("public key hex (compressed): %s\n", hex.EncodeToString(pub.SerializeCompressed()))

	return &ecdsaSigner{privateKey: priv}, nil
}

var (
	rawHexRe = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`)
	b64Re    = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

func newECDSASigner(privateKey string) (*ecdsaSigner, error) {
	if privateKey == "" {
		return nil, errors.New("private key is empty")
	}

	switch {
	case strings.HasPrefix(privateKey, "-----BEGIN"):
		return newECDSASignerFromPem(privateKey)

	case rawHexRe.MatchString(privateKey):
		return newECDSASignerFromHexKey(privateKey)

	case b64Re.MatchString(privateKey):
		decoded, err := base64.StdEncoding.DecodeString(privateKey)
		if err != nil {
			return nil, err
		}
		return newECDSASignerFromPem(string(decoded))

	default:
		return nil, fmt.Errorf("private key is not in a recognized format")
	}
}

func (s *ecdsaSigner) signStringCompact(data string) (string, error) {
	sig, err := s.signBytesCompact([]byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *ecdsaSigner) signBytesCompact(data []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	hash := sha256.Sum256(data)
	return btcecdsa.SignCompact(s.privateKey, hash[:], true), nil
}

func (s *ecdsaSigner) getPublicKey() (*ecdsa.PublicKey, error) {
	if s.privateKey == nil {
		return nil, errors.New("private key is nil")
	}
	return s.privateKey.PubKey().ToECDSA(), nil
}

func (s *ecdsaSigner) getPublicKeyAsPKIX() ([]byte, error) {
	pubKey, err := s.getPublicKey()
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pubKey)
}
