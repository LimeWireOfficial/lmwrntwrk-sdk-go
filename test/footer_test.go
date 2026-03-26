package footer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	footer "github.com/LimeWireOfficial/lmwrntwrk-sdk-go/test"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/client"
	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/server"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestFixedLengthFooterCreationAndValidation(t *testing.T) {
	// Generate a key pair
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	signer := client.NewECDSASigner(privKey)

	// Create test data
	testData := []byte("Hello, world!")
	dataReader := io.NopCloser(bytes.NewReader(testData))

	// Wrap client side reader with footer
	opt := client.FooterOptions{
		ChunkSize:   8,
		EcdsaSigner: signer,
	}
	clientReader, err := client.FooterAppendingReader(dataReader, opt)
	if err != nil {
		t.Fatalf("failed to create footer reader: %v", err)
	}
	log.Printf("SerializeUncompressed: %s", hex.EncodeToString(privKey.PubKey().SerializeUncompressed()))

	// Server side validating reader
	key := client.AddressFromECDSAPub(privKey.PubKey().ToECDSA())

	log.Printf("key: %s", hex.EncodeToString(key))

	validatingReader := server.NewFixedLengthValidatingReader(clientReader, key[:], 109, 8, false)

	// Read from validating reader, collecting the original data
	var out bytes.Buffer
	if _, err := io.Copy(&out, validatingReader); err != nil && err != io.EOF {
		t.Fatalf("reading from validating reader failed: %v", err)
	}

	// Compare original and returned data
	if !bytes.Equal(testData, out.Bytes()) {
		t.Errorf("data mismatch, got=%q want=%q", out.Bytes(), testData)
	}

	if validatingReader.ValidateFooter(key[:]) != nil {
		t.Fatalf("footer validation failed %v", err)
	}
}

func TestFixedLengthOtherFooterCreationAndValidation(t *testing.T) {
	// Generate a key pair
	base64PEM := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUxOcmlRL2RQeGxNUFBWVUsvNVRoNkpETmJsa2poUHJpbFZ2L0xrSmRLZU5vQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFWTN0RE90OUJYZ1AwMDBvQzNBM0hWRjZCTnVIUVlPU3BPVnFudG5rQkNmd0VEd2s1T2xvSgpoUW4yRFZpNUdJeXc2RGQrUk1XVjB6TkY0bmZqTnlyT1VRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	pemBytes, err := base64.StdEncoding.DecodeString(base64PEM)
	if err != nil {
		t.Fatalf("failed to decode base64 PEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to parse PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse EC private key: %v", err)
	}
	if key == nil {
		t.Fatal("private key is nil")
	}
	privKey := key
	private, pub := btcec.PrivKeyFromBytes(privKey.D.Bytes())

	// Create test data
	testData := []byte("Hello, LimeWireNetwork!")
	dataReader := io.NopCloser(bytes.NewReader(testData))

	// Wrap client side reader with footer
	opt := client.FooterOptions{
		ChunkSize:   4096,
		EcdsaSigner: client.NewECDSASigner(private),
	}
	clientReader, err := client.FooterAppendingReader(dataReader, opt)
	if err != nil {
		t.Fatalf("failed to create footer reader: %v", err)
	}

	// Server side validating reader
	validatingReader := server.NewFixedLengthValidatingReader(clientReader, client.AddressFromECDSAPub(pub.ToECDSA()), 109, 4096, false)

	// Read from validating reader, collecting the original data
	var out bytes.Buffer
	if _, err := io.Copy(&out, validatingReader); err != nil && err != io.EOF {
		t.Fatalf("reading from validating reader failed: %v", err)
	}

	// Compare original and returned data
	if !bytes.Equal(testData, out.Bytes()) {
		t.Errorf("data mismatch, got=%q want=%q", out.Bytes(), testData)
	}

	if validatingReader.ValidateFooter(client.AddressFromECDSAPub(pub.ToECDSA())) != nil {
		t.Fatalf("footer validation failed %v", err)
	}

}

func TestFixedLengthFooterWithFile(t *testing.T) {
	chunkSizes := []int{8, 64, 256, 1024, 1025, 2048, 4096}
	//chunkSizes := []int{4096}
	for _, chunkSize := range chunkSizes {
		t.Run(fmt.Sprintf("chunkSize=%d", chunkSize), func(t *testing.T) {
			// Generate a key pair
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate private key: %v", err)
			}

			// Open a file from the project (using this test file)
			file, err := os.Open("testdata/limewire_network_logo_white.svg")
			if err != nil {
				t.Fatalf("failed to open test file: %v", err)
			}
			defer file.Close()

			// Read file content
			fileContent, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}
			// Reset file pointer
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatalf("failed to seek test file: %v", err)
			}

			private, pub := btcec.PrivKeyFromBytes(privKey.D.Bytes())

			// Wrap client side reader with footer
			opt := client.FooterOptions{
				ChunkSize:   chunkSize,
				EcdsaSigner: client.NewECDSASigner(private),
			}
			clientReader, err := client.FooterAppendingReader(file, opt)
			if err != nil {
				t.Fatalf("failed to create footer reader: %v", err)
			}

			everything, err := ReadAllWithChunkSize(clientReader, chunkSize)
			validatingReader := server.NewFixedLengthValidatingReader(bytes.NewReader(everything), client.AddressFromECDSAPub(pub.ToECDSA()), 109, chunkSize, false)

			// Server side validating reader
			//validatingReader := server.NewFixedLengthValidatingReader(clientReader, client.AddressFromECDSAPub(pub.ToECDSA()), 109, chunkSize)

			// Read from validating reader, collecting the original data
			var out bytes.Buffer
			if _, err := io.Copy(&out, validatingReader); err != nil && err != io.EOF {
				t.Fatalf("reading from validating reader failed: %v", err)
			}

			// Compare original and returned data
			if !bytes.Equal(fileContent, out.Bytes()) {
				t.Errorf("data mismatch, got=%d bytes, want=%d bytes", len(out.Bytes()), len(fileContent))
			}

			if validatingReader.ValidateFooter(client.AddressFromECDSAPub(pub.ToECDSA())) != nil {
				t.Fatalf("footer validation failed %v", err)
			}
		})
	}
}

func TestFixedLengthPartialReadDuringProcessing(t *testing.T) {
	chunkSize := 4096
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	file, err := os.Open("testdata/test-image.png")
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer file.Close()
	fileContent, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	// Reset file pointer
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("failed to seek test file: %v", err)
	}

	private, pub := btcec.PrivKeyFromBytes(privKey.D.Bytes())

	// Wrap client side reader with footer
	opt := client.FooterOptions{
		ChunkSize:   chunkSize,
		EcdsaSigner: client.NewECDSASigner(private),
	}

	clientReader, err := client.FooterAppendingReader(file, opt)
	if err != nil {
		t.Fatalf("failed to create footer reader: %v", err)
	}
	everything, err := ReadAllWithChunkSize(clientReader, chunkSize)
	chunkedReader := footer.NewChunkedReader(everything, []int{4096, 4096, 4096, 3332, 4096, 4096, 4096})

	// Server side validating reader
	validatingReader := server.NewFixedLengthValidatingReader(chunkedReader, client.AddressFromECDSAPub(pub.ToECDSA()), 109, chunkSize, false)
	if err != nil {
		t.Fatalf("failed to create footer: %v", err)
	}

	// Read from validating reader, collecting the original data
	/*
		var out bytes.Buffer
		if _, err := io.Copy(&out, validatingReader); err != nil && err != io.EOF {
			t.Fatalf("reading from validating reader failed: %v", err)
		}
	*/
	resultData, err := ReadAllWithChunkSize(validatingReader, chunkSize)
	if err != nil {
		t.Fatalf("failed to read footer: %v", err)
	}

	// Compare original and returned data
	if !bytes.Equal(fileContent, resultData) {
		t.Errorf("data mismatch, got=%d bytes, want=%d bytes", len(resultData), len(fileContent))
	}

	if validatingReader.ValidateFooter(client.AddressFromECDSAPub(pub.ToECDSA())) != nil {
		t.Fatalf("footer validation failed %v", err)
	}
}

func TestFixedLengthCutOffMagicBytes(t *testing.T) {
	chunkSize := 4096
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	file, err := os.Open("testdata/test-image.png")
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer file.Close()
	fileContent, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	// Reset file pointer
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("failed to seek test file: %v", err)
	}

	private, pub := btcec.PrivKeyFromBytes(privKey.D.Bytes())

	// Wrap client side reader with footer
	opt := client.FooterOptions{
		ChunkSize:   chunkSize,
		EcdsaSigner: client.NewECDSASigner(private),
	}

	clientReader, err := client.FooterAppendingReader(file, opt)
	if err != nil {
		t.Fatalf("failed to create footer reader: %v", err)
	}
	everything, err := ReadAllWithChunkSize(clientReader, chunkSize)
	// read chunks so the magic bytes are exactly cut off...
	// if the input file changes this needs to be adapted
	chunkedReader := footer.NewChunkedReader(everything, []int{4069, 4069, 4069, 4069, 4069, 505})

	// Server side validating reader
	validatingReader := server.NewFixedLengthValidatingReader(chunkedReader, client.AddressFromECDSAPub(pub.ToECDSA()), 109, chunkSize, false)
	if err != nil {
		t.Fatalf("failed to create footer: %v", err)
	}

	resultData, err := ReadAllWithChunkSize(validatingReader, chunkSize)
	if err != nil {
		t.Fatalf("failed to read footer: %v", err)
	}

	// Compare original and returned data
	if !bytes.Equal(fileContent, resultData) {
		t.Errorf("data mismatch, got=%d bytes, want=%d bytes", len(resultData), len(fileContent))
	}

	if validatingReader.ValidateFooter(client.AddressFromECDSAPub(pub.ToECDSA())) != nil {
		t.Fatalf("footer validation failed %v", err)
	}
}

func TestWithoutFooter(t *testing.T) {
	file, err := os.Open("testdata/test-image.png")
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer file.Close()

	fileContent, _ := io.ReadAll(file)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	_, pub := btcec.PrivKeyFromBytes(privKey.D.Bytes())

	validatingReader := server.NewFixedLengthValidatingReader(bytes.NewReader(fileContent), client.AddressFromECDSAPub(pub.ToECDSA()), 0, 4096, false)
	content, err := io.ReadAll(validatingReader)

	if !bytes.Equal(content, fileContent) {
		t.Errorf("data mismatch, got=%d bytes, want=%d bytes", len(fileContent), len(content))
	}

	if len(validatingReader.GetFooterBytes()) > 0 {
		t.Errorf("Should not have footer")
	}
}

func ReadAllWithChunkSize(r io.Reader, chunkSize int) ([]byte, error) {
	if chunkSize <= 0 {
		return nil, errors.New("chunk size must be greater than zero")
	}

	// A buffer to hold the entire data
	var result []byte

	// A temporary buffer to read chunks
	tmp := make([]byte, chunkSize)

	// Read in chunks till EOF
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			result = append(result, tmp[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil { // Handle errors
			return nil, err
		}
	}

	return result, nil
}
