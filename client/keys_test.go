package client

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestSha256(t *testing.T) {
	input := []byte("lmwrntwrk")
	expected := "a90cbb4d9f6010d7811b47e9671901560ccd64c7139e08287d5ed3cd094d3ffa"
	result := sha256.Sum256(input)
	resultHex := hex.EncodeToString(result[:])
	if resultHex != expected {
		t.Errorf("expected %s, got %s", expected, resultHex)
	}
}

func TestBase58Encode(t *testing.T) {
	input := []byte("lmwrntwrk")
	expected := "2P3oCPUfUD4ug"
	result := base58Encode(input)
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestGetAccessKey_ValidKey(t *testing.T) {
	b64pem, _, err := generateTestECDSAPrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}
	key := GenerateAccessKey(cfg)
	if key == "" {
		t.Error("expected non-empty access key")
	}
	if len(key) > 20 {
		t.Errorf("access key should be at most 20 chars, got %d", len(key))
	}
}

func TestGetAccessKey_ValidKey_Static(t *testing.T) {
	const base64Key = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUtFVUtma2tDM1N5QWcxTjhYRVNZZENueVBUWnVlOWNweUpRWlpyRzJvZjlvQWNHQlN1QkJBQUsKb1VRRFFnQUVSb3BjMWlKbk52VGEyT1NvT2FIYVZtTDF1V2hxTEc4Q0Q0QnQrc3lqOFgzMlJiYlc2aVd3cldRZwpzcEhieDY3MTBpRmhjdUhzNE4xWGozc2FxZmJ3ekE9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCg=="

	cfg := Config{PrivateKey: base64Key}
	access := GenerateAccessKey(cfg)

	if access == "" {
		t.Fatalf("expected non-empty access key")
	}
	// Assert against the expected value derived for this key
	if access != "3UAdfsZgqZuJa8PZi9jS" {
		t.Fatalf("unexpected access key: got %q, want %q", access, "3UAdfsZgqZuJa8PZi9jS")
	}
}

func TestGetSecretKey_ValidKey_Static(t *testing.T) {
	const base64Key = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUtFVUtma2tDM1N5QWcxTjhYRVNZZENueVBUWnVlOWNweUpRWlpyRzJvZjlvQWNHQlN1QkJBQUsKb1VRRFFnQUVSb3BjMWlKbk52VGEyT1NvT2FIYVZtTDF1V2hxTEc4Q0Q0QnQrc3lqOFgzMlJiYlc2aVd3cldRZwpzcEhieDY3MTBpRmhjdUhzNE4xWGozc2FxZmJ3ekE9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCg=="

	cfg := Config{PrivateKey: base64Key}
	key := GenerateSecretKey(cfg)
	if key == "" {
		t.Error("expected non-empty secret key")
	}
	if key != "62b5dd60e3427e4def3ebfe51e0f7f142fefc683" {
		t.Errorf("unexpected secret key: got %q, want %q", key, "62b5dd60e3427e4def3ebfe51e0f7f142fefc683")
	}
}

func TestGetAccessKey_ValidKeySecp256k1(t *testing.T) {
	b64pem, _, err := generateTestSecp256k1PrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}
	key := GenerateAccessKey(cfg)
	if key == "" {
		t.Error("expected non-empty access key")
	}
	if len(key) > 20 {
		t.Errorf("access key should be at most 20 chars, got %d", len(key))
	}
}

func TestGetSecretKey_ValidKey(t *testing.T) {
	b64pem, _, err := generateTestECDSAPrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cfg := Config{PrivateKey: b64pem}
	key := GenerateSecretKey(cfg)
	if key == "" {
		t.Error("expected non-empty secret key")
	}
}

func TestGetAccessKey_InvalidKey(t *testing.T) {
	cfg := Config{PrivateKey: "not-base64"}
	key := GenerateAccessKey(cfg)
	if key != "" {
		t.Error("expected empty access key for invalid PEM")
	}
}

func TestGetSecretKey_InvalidKey(t *testing.T) {
	cfg := Config{PrivateKey: "not-base64"}
	key := GenerateSecretKey(cfg)
	if key != "" {
		t.Error("expected empty secret key for invalid PEM")
	}
}

func TestAddressFromUncompressedPublicKey(t *testing.T) {
	input, _ := hex.DecodeString("fe3ffc5b3e9919868927a6bc6304c7a884b85f0539fa663079b8412b8bb876c0ce3c9a5760be46304416690f52322b8b07d5d0eb6d5537202c473d22d4010cc0")
	address := shared.AddressFromUncompressed(input)
	hexAddress := hex.EncodeToString(address[:])
	if hexAddress != "30bf0af6137b4b039d40a475c5d1c5d59c01cfc3" {
		t.Errorf("expected %s, got %s", "30bf0af6137b4b039d40a475c5d1c5d59c01cfc3", hexAddress)
	}
}

// helper to build ECDSA public key from 32-byte X and Y big.Ints on secp256k1
func makePubKey(xHex, yHex string) *ecdsa.PublicKey {
	x := new(big.Int)
	y := new(big.Int)
	x.SetString(xHex, 16)
	y.SetString(yHex, 16)
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}
}

func TestAddressFromECDSAPub_KnownVector(t *testing.T) {
	// Sample uncompressed public key (from a valid secp256k1 point)
	// 04 + X + Y (we only need X and Y)
	x := "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	y := "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

	pub := makePubKey(x, y)

	got := AddressFromECDSAPub(pub)

	// Build expected XY (left-padded 32 bytes per coordinate)
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	var xy [64]byte
	copy(xy[32-len(xBytes):32], xBytes)
	copy(xy[64-len(yBytes):], yBytes)

	want := shared.AddressFromUncompressed(xy[:])
	// print wanted as hex
	wantHex := hex.EncodeToString(want[:])
	t.Logf("want: %s", wantHex)

	if len(got) != len(want) {
		t.Fatalf("unexpected address length: got=%d want=%d", len(got), len(want))
	}
	if string(got) != string(want) {
		t.Fatalf("address mismatch:\n got:  %x\n want: %x", got, want)
	}
}

func TestAddressFromECDSAPub_ParityPadding(t *testing.T) {
	// Use two valid points with different Y parity to ensure padding/order unaffected.
	// Start from generator G and 2G
	priv1 := secp256k1.PrivKeyFromBytes(make([]byte, 32)) // zero is invalid; create 1 instead
	one := make([]byte, 32)
	one[31] = 1
	priv1 = secp256k1.PrivKeyFromBytes(one)

	pub1 := priv1.PubKey().ToECDSA()

	// 2G: add G+G
	two := make([]byte, 32)
	two[31] = 2
	priv2 := secp256k1.PrivKeyFromBytes(two)
	pub2 := priv2.PubKey().ToECDSA()

	for _, pub := range []*ecdsa.PublicKey{pub1, pub2} {
		got := AddressFromECDSAPub(pub)

		xBytes := pub.X.Bytes()
		yBytes := pub.Y.Bytes()
		var xy [64]byte
		copy(xy[32-len(xBytes):32], xBytes)
		copy(xy[64-len(yBytes):], yBytes)
		want := shared.AddressFromUncompressed(xy[:])

		if string(got) != string(want) {
			t.Fatalf("address mismatch for pub with Y LSB=%d:\n got:  %x\n want: %x", pub.Y.Bit(0), got, want)
		}
	}
}
