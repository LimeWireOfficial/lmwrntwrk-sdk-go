package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

type Footer struct {
	magicBytes   []byte
	hashesDigest []byte
	sizeBytes    []byte
	sig          []byte
	fileSize     int64
}

func NewFooter(input []byte) *Footer {
	if len(input) < 108 {
		panic("invalid footer")
	}

	sizeBytes := input[36:44]

	return &Footer{
		// first 3 bytes are the magic bytes
		// next byte is the version
		// so we start at 4
		magicBytes:   input[:3],
		hashesDigest: input[4:36],
		sizeBytes:    sizeBytes,
		sig:          input[44:109],
		fileSize:     int64(binary.BigEndian.Uint64(sizeBytes)),
	}
}

func (f *Footer) Validate(expectedKey []byte, expectedSize int64, hashes []HashWithLength) error {
	if expectedSize != f.fileSize {
		return errors.New(fmt.Sprintf("Footer File Size mismatch, expected %d got %d", expectedSize, f.fileSize))
	}

	hasher := sha256.New()
	for _, h := range hashes {
		hasher.Write(h.Hash)
	}
	computedDigest := hasher.Sum(nil)
	if !bytes.Equal(f.hashesDigest, computedDigest) {
		return errors.New(fmt.Sprintf("Footer Hash Digest mismatch, expected %d got %d", f.hashesDigest, computedDigest))
	}

	// Prepare signature input: hashesDigest + sizeBytes
	sigInput := append(f.hashesDigest, f.sizeBytes...)
	sigHash := sha256.Sum256(sigInput)

	key, _, err := btcecdsa.RecoverCompact(f.sig, sigHash[:])
	if err != nil {
		return errors.New("Footer Signature Verification failed - Could not recover public key")
	}

	recoveredAddress := shared.AddressFromUncompressed(key.SerializeUncompressed())

	if !bytes.Equal(recoveredAddress, expectedKey) {
		return errors.New("Recovered Address does not match PublicKey")
	}

	return nil
}
