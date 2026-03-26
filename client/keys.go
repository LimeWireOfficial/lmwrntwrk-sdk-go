package client

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"fmt"
	"math/big"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
)

// GenerateAccessKey generates a S3-compatible access key from config.
// Returns the first 20 characters of the base58 encoded SHA-1 hash of the public key bytes.
func GenerateAccessKey(cfg Config) string {
	privateKey, err := cfg.GetPrivateKey()
	if err != nil {
		return ""
	}
	signer, err := newECDSASigner(privateKey)
	if err != nil || signer.privateKey == nil {
		return ""
	}
	pubKeyBytes := AddressFromECDSAPub(signer.privateKey.PubKey().ToECDSA())
	return GenerateAccessKeyFromPublicKeyBytes(pubKeyBytes[:])
}

// GenerateAccessKeyFromPublicKeyBytes generates a S3-compatible access key from public key bytes in PKIX format.
// Returns the first 20 characters of the base58 encoded SHA-1 hash of the public key bytes.
func GenerateAccessKeyFromPublicKeyBytes(pubKeyBytes []byte) string {
	if len(pubKeyBytes) == 0 {
		return ""
	}
	base58Str := base58Encode(pubKeyBytes)
	if len(base58Str) > 20 {
		return base58Str[:20]
	}
	return base58Str
}

// GenerateSecretKey generates a S3-compatible secret key from config.
func GenerateSecretKey(cfg Config) string {
	privateKey, err := cfg.GetPrivateKey()
	if err != nil {
		return ""
	}
	signer, err := newECDSASigner(privateKey)
	if err != nil || signer.privateKey == nil {
		return ""
	}
	pubKeyBytes := AddressFromECDSAPub(signer.privateKey.PubKey().ToECDSA())
	return GenerateSecretKeyFromPublicKeyBytes(pubKeyBytes[:])
}

// GenerateSecretKeyFromPublicKeyBytes generates a S3-compatible secret key from public key bytes in PKIX format.
func GenerateSecretKeyFromPublicKeyBytes(pubKeyBytes []byte) string {
	if len(pubKeyBytes) == 0 {
		return ""
	}
	hash := sha1Sum(pubKeyBytes)
	return fmt.Sprintf("%x", hash)
}

// sha1Sum returns the SHA-1 hash of the input.
func sha1Sum(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// base58Encode encodes bytes to a base58 string.
func base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := new(big.Int).SetBytes(input)
	var result []byte
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append([]byte{alphabet[mod.Int64()]}, result...)
	}
	return string(result)
}

func AddressFromECDSAPub(pub *ecdsa.PublicKey) []byte {
	// Ensure curve is secp256k1 if this is for Ethereum
	// pub.Curve should be secp256k1; get one via btcec/v2 or github.com/decred/dcrd/dcrec/secp256k1/v4
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Left-pad to 32 bytes each
	var xy [64]byte
	copy(xy[32-len(xBytes):32], xBytes)
	copy(xy[64-len(yBytes):], yBytes)
	return shared.AddressFromUncompressed(xy[:])
}
