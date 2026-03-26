package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func generateTestECDSAPrivateKeyPEM() (string, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", nil, err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), priv, nil
}

// generate secp256k1 using btcec package
func generateTestSecp256k1PrivateKeyPEM() (string, *ecdsa.PrivateKey, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, err
	}

	// priv.Serialize() returns the private key as a 256-bit big-endian number padded to 32 bytes.
	// Wrap it as SEC1 ECPrivateKey (DER) so that newECDSASigner can parse it under "EC PRIVATE KEY".
	sec1 := sec1ECPrivateKey{
		Version:    1,
		PrivateKey: priv.Serialize(),
	}
	der, err := asn1.Marshal(sec1)
	if err != nil {
		return "", nil, err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), priv.ToECDSA(), nil
}

func TestNewECDSASigner_ValidKey(t *testing.T) {
	b64pem, _, err := generateTestECDSAPrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer, got nil")
	}
}

func TestNewECDSASigner_InvalidBase64(t *testing.T) {
	_, err := newECDSASigner("not-base64")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestNewECDSASigner_InvalidPEM(t *testing.T) {
	badPEM := base64.StdEncoding.EncodeToString([]byte("not a pem"))
	_, err := newECDSASigner(badPEM)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestSignStringWithRecovery(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data := "test message"
	sig, err := signer.signStringCompact(data)
	if err != nil {
		t.Fatalf("signString failed: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature not base64: %v", err)
	}
	hash := sha256.Sum256([]byte(data))

	publicKey, result, err := btcecdsa.RecoverCompact(sigBytes, hash[:])
	if !result {
		t.Error("signature verification failed")
	}

	if !signer.privateKey.PubKey().IsEqual(publicKey) {
		t.Error("publickey does not match")
	}
}

func TestVerifySignatureWithStandardMechanism(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data := "test message"
	sig, err := signer.signStringCompact(data)
	if err != nil {
		t.Fatalf("signString failed: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature not base64: %v", err)
	}
	hash := sha256.Sum256([]byte(data))

	r := new(big.Int).SetBytes(sigBytes[1:33])
	s := new(big.Int).SetBytes(sigBytes[33:65])
	result := ecdsa.Verify(signer.privateKey.PubKey().ToECDSA(), hash[:], r, s)
	if !result {
		t.Error("signature verification failed")
	}
}

func TestSignString_ErrorOnNilKey(t *testing.T) {
	signer := &ecdsaSigner{privateKey: nil}
	_, err := signer.signStringCompact("data")
	if err == nil {
		t.Error("expected error when signing with nil key")
	}
}

func TestSignStringWithFixedKeyFromPem_LimeWireNetwork(t *testing.T) {
	pemB64 := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUtFVUtma2tDM1N5QWcxTjhYRVNZZENueVBUWnVlOWNweUpRWlpyRzJvZjlvQWNHQlN1QkJBQUsKb1VRRFFnQUVSb3BjMWlKbk52VGEyT1NvT2FIYVZtTDF1V2hxTEc4Q0Q0QnQrc3lqOFgzMlJiYlc2aVd3cldRZwpzcEhieDY3MTBpRmhjdUhzNE4xWGozc2FxZmJ3ekE9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCg=="
	signer, err := newECDSASigner(pemB64)
	if err != nil {
		t.Fatalf("newECDSASigner failed: %v", err)
	}

	msg := "lmwrntwrk"
	sigB64, err := signer.signStringCompact(msg)
	if err != nil {
		t.Fatalf("signStringCompact failed: %v", err)
	}
	if sigB64 == "" {
		t.Fatalf("compact signature is empty")
	}

	expectedSig := "H98j93R+X5B07+ZhCXlwgN/YMUx8xEgHzihfAc+TXWLdRgpXiDP/CrIwOQM9hk+X3MJ5iA6k1+xIH3kdNqFLQx4="
	if sigB64 != expectedSig {
		t.Fatalf("unexpected signature: got %s, want %s", sigB64, expectedSig)
	}
}

func TestSignStringWithFixedKey_LimeWireNetwork(t *testing.T) {
	// Fixed secp256k1 private key (hex)
	keyHex := "a11429f9240b74b2020d4df1711261d0a7c8f4d9b9ef5ca72250659ac6da87fd"
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	// Create btcec private key from raw bytes
	priv, _ := btcec.PrivKeyFromBytes(keyBytes)

	// Prepare a PEM-like block where Bytes is the raw key material we accept in newECDSASigner
	block := &pem.Block{
		Type:  "EC RAW PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemBytes := pem.EncodeToMemory(block)
	b64pem := base64.StdEncoding.EncodeToString(pemBytes)

	// Build signer
	signer, err := newECDSASigner(b64pem)
	if err != nil {
		t.Fatalf("newECDSASigner failed: %v", err)
	}

	// Sign the message
	msg := "lmwrntwrk"
	sigB64, err := signer.signStringCompact(msg)
	if err != nil {
		t.Fatalf("signStringCompact failed: %v", err)
	}

	// assert signature has value
	if sigB64 == "" {
		t.Fatalf("signature is empty")
	}
	expectedSig := "H98j93R+X5B07+ZhCXlwgN/YMUx8xEgHzihfAc+TXWLdRgpXiDP/CrIwOQM9hk+X3MJ5iA6k1+xIH3kdNqFLQx4="
	if sigB64 != expectedSig {
		t.Fatalf("unexpected signature: got %s, want %s", sigB64, expectedSig)
	}

	// Verify via public key recovery
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("signature not base64: %v", err)
	}
	hash := sha256.Sum256([]byte(msg))
	pubRecovered, ok, err := btcecdsa.RecoverCompact(sigBytes, hash[:])
	if err != nil {
		t.Fatalf("RecoverCompact error: %v", err)
	}
	if !ok {
		t.Fatalf("recovered signature did not verify")
	}
	if !pubRecovered.IsEqual(priv.PubKey()) {
		t.Fatalf("recovered public key mismatch")
	}
}
