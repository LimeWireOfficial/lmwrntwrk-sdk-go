package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
	"github.com/btcsuite/btcd/btcec/v2"
)

// mockReadCloser wraps a reader with a Close method
type mockReadCloser struct {
	io.Reader
	closed bool
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

// newTestSigner creates a test ECDSA signer using btcec
func newTestSigner(t *testing.T) (*ecdsaSigner, []byte) {
	t.Helper()
	privKeyBytes, err := hex.DecodeString("8870cfc22e8d150220a76192bba8b9ec76e71c7af11bf6dc83fe12c3cd384211")
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	return NewECDSASigner(priv), AddressFromECDSAPub(priv.PubKey().ToECDSA())
}

func TestFooterReader_Read_EmptyBody(t *testing.T) {
	body := &mockReadCloser{Reader: bytes.NewReader([]byte{})}
	signer, _ := newTestSigner(t)

	reader, err := FooterAppendingReader(body, FooterOptions{
		ChunkSize:   1024,
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := reader.Read(buf)

	// Should read the footer since body is empty
	if err != nil && err != io.EOF {
		t.Errorf("Expected no error or EOF, got: %v", err)
	}
	if n == 0 {
		t.Error("Expected to read footer bytes, got 0")
	}
}

func TestFooterReader_Read_SingleChunk(t *testing.T) {
	testData := []byte("Hello, World!")
	body := &mockReadCloser{Reader: bytes.NewReader(testData)}
	signer, _ := newTestSigner(t)

	reader, err := FooterAppendingReader(body, FooterOptions{
		ChunkSize:   1024,
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader failed: %v", err)
	}

	// Read the data chunk
	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil {
		t.Errorf("First read failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to read %d bytes, got %d", len(testData), n)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("Data mismatch: expected %v, got %v", testData, buf[:n])
	}

	// Read the footer
	n, err = reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("Footer read error: %v", err)
	}
	if n == 0 {
		t.Error("Expected to read footer bytes")
	}

	log.Printf("Read footer: %s", hex.EncodeToString(buf[:n]))
}

func TestFooterReader_Read_MultipleChunks(t *testing.T) {
	// Create data larger than chunk size
	testData := bytes.Repeat([]byte("A"), 2048)
	body := &mockReadCloser{Reader: bytes.NewReader(testData)}
	signer, _ := newTestSigner(t)

	reader, err := FooterAppendingReader(body, FooterOptions{
		ChunkSize:   1024,
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader failed: %v", err)
	}

	var readData bytes.Buffer
	buf := make([]byte, 1024)
	chunksRead := 0

	// Read all chunks
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			readData.Write(buf[:n])
			chunksRead++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}

	// Verify we read the data (footer will be appended)
	if readData.Len() < len(testData) {
		t.Errorf("Expected to read at least %d bytes, got %d", len(testData), readData.Len())
	}
	if chunksRead < 2 {
		t.Errorf("Expected at least 2 chunks for data > chunk size, got %d", chunksRead)
	}
}

func TestFooterReader_Close(t *testing.T) {
	body := &mockReadCloser{Reader: bytes.NewReader([]byte("test"))}
	signer, _ := newTestSigner(t)

	reader, err := FooterAppendingReader(body, FooterOptions{
		ChunkSize:   1024,
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader failed: %v", err)
	}

	err = reader.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !body.closed {
		t.Error("Expected underlying body to be closed")
	}
}

func TestFooterAppendingReader_ReturnValues(t *testing.T) {
	body := &mockReadCloser{Reader: bytes.NewReader([]byte("test"))}
	signer, _ := newTestSigner(t)

	reader, err := FooterAppendingReader(body, FooterOptions{
		ChunkSize:   1024,
		EcdsaSigner: signer,
	})

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if reader == nil {
		t.Error("Expected non-nil reader")
	}
}

func TestCreateFooter_Structure(t *testing.T) {
	signer, _ := newTestSigner(t)
	testData := []byte("test data")
	hash := sha256.Sum256(testData)
	hashes := []HashWithLength{{
		Hash:   hash[:],
		Length: len(testData)}}
	total := int64(len(testData))

	// TODO: verify returned Payload
	footer, _, err := createFooter(hashes, total, signer)
	if err != nil {
		t.Fatalf("createFooter failed: %v", err)
	}

	// Verify footer structure
	if len(footer) < len(shared.MagicBytes)+1+32+8 {
		t.Errorf("Footer too short: %d bytes", len(footer))
	}

	// Check magic bytes
	if !bytes.Equal(footer[:len(shared.MagicBytes)], shared.MagicBytes) {
		t.Error("Magic bytes mismatch")
	}

	offset := len(shared.MagicBytes)

	// Check version
	version := footer[offset]
	if version != 1 {
		t.Errorf("Expected version 1, got: %d", version)
	}
	offset++

	// Check hashes digest (32 bytes)
	hashesDigest := footer[offset : offset+32]
	expectedHasher := sha256.New()
	for _, h := range hashes {
		expectedHasher.Write(h.Hash)
	}
	expectedDigest := expectedHasher.Sum(nil)
	if !bytes.Equal(hashesDigest, expectedDigest) {
		t.Error("Hashes digest mismatch")
	}
	offset += 32

	// Check size bytes
	sizeBytes := footer[offset : offset+8]
	size := binary.BigEndian.Uint64(sizeBytes)
	if size != uint64(total) {
		t.Errorf("Expected size %d, got: %d", total, size)
	}
	offset += 8

	// Verify signature exists
	if len(footer) <= offset {
		t.Error("Footer missing signature")
	}
}

func TestCreateFooter_MultipleHashes(t *testing.T) {
	signer, _ := newTestSigner(t)

	// Create multiple hashes
	var hashes []HashWithLength
	for i := 0; i < 5; i++ {
		data := []byte{byte(i)}
		hash := sha256.Sum256(data)
		hashes = append(hashes, HashWithLength{Hash: hash[:], Length: len(data)})
	}
	total := int64(5)
	// TODO: verify returned Payload
	footer, _, err := createFooter(hashes, total, signer)
	if err != nil {
		t.Fatalf("createFooter failed: %v", err)
	}

	if len(footer) == 0 {
		t.Error("Expected non-empty footer")
	}

	// Verify magic bytes present
	if !bytes.HasPrefix(footer, shared.MagicBytes) {
		t.Error("Footer missing magic bytes")
	}
}

func TestCreateFooter_ZeroTotal(t *testing.T) {
	signer, _ := newTestSigner(t)
	var hashes []HashWithLength
	total := int64(0)

	// TODO: verify returned Payload
	footer, _, err := createFooter(hashes, total, signer)
	if err != nil {
		t.Fatalf("createFooter failed: %v", err)
	}

	if len(footer) == 0 {
		t.Error("Expected non-empty footer even with zero total")
	}
}

func TestFooterReader_ConsecutiveReads(t *testing.T) {
	testData := []byte("Small data")
	body := &mockReadCloser{Reader: bytes.NewReader(testData)}
	signer, _ := newTestSigner(t)

	reader, err := FooterAppendingReader(body, FooterOptions{
		ChunkSize:   1024, // Use chunk size larger than data
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader failed: %v", err)
	}

	var allData bytes.Buffer
	buf := make([]byte, 5) // Small read buffer

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			allData.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}

	// Should have read original data plus footer
	if allData.Len() <= len(testData) {
		t.Errorf("Expected to read more than %d bytes (data + footer), got %d", len(testData), allData.Len())
	}

	// Verify original data is preserved at the start
	if !bytes.HasPrefix(allData.Bytes(), testData) {
		t.Errorf("Original data not preserved. Expected prefix: %q, got: %q", testData, allData.Bytes()[:minF(len(testData), allData.Len())])
	}
}

func minF(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Integration tests from reference file

func TestFooterReader_AppendsFooter_LimeWireNetworkData(t *testing.T) {
	// One example should add appropriate footer for the data "lmwrntwrk"
	data := []byte("lmwrntwrk")
	rc := io.NopCloser(bytes.NewReader(data))

	signer, _ := newTestSigner(t)

	r, err := FooterAppendingReader(rc, FooterOptions{
		ChunkSize:   4, // small chunk to exercise hashing over multiple reads
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader: %v", err)
	}
	defer r.Close()

	var out bytes.Buffer
	n, err := io.Copy(&out, r)
	if err != nil && err != io.EOF {
		t.Fatalf("copy: %v", err)
	}
	if n <= int64(len(data)) {
		t.Fatalf("expected more bytes than data length, got %d", n)
	}
	got := out.Bytes()
	if !bytes.HasPrefix(got, data) {
		t.Fatalf("payload not preserved at beginning")
	}
	fmt.Printf("got: %x\n", got)

	// Find magic safely (don't assume exact offset)
	magic := shared.MagicBytes
	idx := bytes.Index(got[len(data):], magic)
	fmt.Printf("idx: %d\n", idx)
	if idx < 0 {
		t.Fatalf("magic not found in stream tail")
	}
	footer := got[len(data)+idx:]
	minFooter := len(magic) + 1 + 32 + 8 + 64
	if len(footer) < minFooter {
		t.Fatalf("footer too short; len=%d", len(footer))
	}
	// print footer
	fmt.Printf("footer: %x\n", footer)
	if !bytes.Equal(footer[0:len(magic)], magic) {
		t.Fatalf("unexpected magic bytes: %x", footer[0:len(magic)])
	}
	if footer[len(magic)] != 1 {
		t.Fatalf("unexpected footer version: %d", footer[len(magic)])
	}
}

func TestFooterReader_ReadsAndAppendsFooter_RandomData(t *testing.T) {
	// Random payload to ensure hashing path is exercised
	payload := make([]byte, 10*1024+123) // span multiple chunks
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	rc := io.NopCloser(bytes.NewReader(payload))

	signer, _ := newTestSigner(t)

	r, err := FooterAppendingReader(rc, FooterOptions{
		ChunkSize:   1024,
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader: %v", err)
	}
	defer r.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil && err != io.EOF {
		t.Fatalf("copy: %v", err)
	}

	got := out.Bytes()
	if !bytes.HasPrefix(got, payload) {
		t.Fatalf("payload not preserved")
	}

	magic := shared.MagicBytes
	idx := bytes.Index(got[len(payload):], magic)
	if idx < 0 {
		t.Fatalf("magic not found in stream tail")
	}
	footer := got[len(payload)+idx:]
	minFooter := len(magic) + 1 + 32 + 8 + 64
	if len(footer) < minFooter {
		t.Fatalf("footer too short; len=%d", len(footer))
	}
	if !bytes.Equal(footer[0:len(magic)], magic) {
		t.Fatalf("unexpected magic bytes: %x", footer[0:len(magic)])
	}
	if footer[len(magic)] != 1 {
		t.Fatalf("unexpected footer version: %d", footer[len(magic)])
	}
}

func TestFooterReader_EmptyPayload_StillHasFooter(t *testing.T) {
	rc := io.NopCloser(bytes.NewReader(nil))
	signer, _ := newTestSigner(t)

	r, err := FooterAppendingReader(rc, FooterOptions{
		ChunkSize:   8,
		EcdsaSigner: signer,
	})
	if err != nil {
		t.Fatalf("FooterAppendingReader: %v", err)
	}
	defer r.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil && err != io.EOF {
		t.Fatalf("copy: %v", err)
	}

	got := out.Bytes()
	magic := shared.MagicBytes
	idx := bytes.Index(got, magic)
	if idx < 0 {
		t.Fatalf("magic not found")
	}
	footer := got[idx:]
	if len(footer) < len(magic)+1 {
		t.Fatalf("footer too short")
	}
	if !bytes.Equal(footer[0:len(magic)], magic) {
		t.Fatalf("unexpected magic bytes: %x", footer[0:len(magic)])
	}
	if footer[len(magic)] != 1 {
		t.Fatalf("unexpected footer version: %d", footer[len(magic)])
	}
}

func BenchmarkFooterReader_SmallData(b *testing.B) {
	testData := bytes.Repeat([]byte("A"), 1024)
	signer, _ := newTestSigner(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body := io.NopCloser(bytes.NewReader(testData))
		reader, _ := FooterAppendingReader(body, FooterOptions{
			ChunkSize:   512,
			EcdsaSigner: signer,
		})

		buf := make([]byte, 512)
		for {
			_, err := reader.Read(buf)
			if err == io.EOF {
				break
			}
		}
	}
}

func BenchmarkFooterReader_LargeData(b *testing.B) {
	testData := bytes.Repeat([]byte("A"), 1024*1024) // 1MB
	signer, _ := newTestSigner(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body := io.NopCloser(bytes.NewReader(testData))
		reader, _ := FooterAppendingReader(body, FooterOptions{
			ChunkSize:   4096,
			EcdsaSigner: signer,
		})

		buf := make([]byte, 4096)
		for {
			_, err := reader.Read(buf)
			if err == io.EOF {
				break
			}
		}
	}
}
