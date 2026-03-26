package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/LimeWireOfficial/lmwrntwrk-sdk-go/internal/shared"
)

type FooterOptions struct {
	ChunkSize   int
	EcdsaSigner *ecdsaSigner
}

type FooterReader struct {
	body      io.ReadCloser
	chunkSize int
	hashes    []HashWithLength
	buf       []byte
	footer    []byte
	pos       int
	eof       bool
	total     int64
	signer    *ecdsaSigner

	bufPos int
	bufLen int

	validatorPayload *ValidatorPayload
}

type ValidatorPayload struct {
	Signature []byte
	TotalSize int64
	Hashes    []HashWithLength
}

type HashWithLength struct {
	Hash   []byte
	Length int
}

func (r *FooterReader) Read(p []byte) (int, error) {
	if r.eof {
		if r.footer == nil {
			var err error
			r.footer, r.validatorPayload, err = createFooter(r.hashes, r.total, r.signer)
			if err != nil {
				return 0, err
			}
		}
		if r.pos >= len(r.footer) {
			return 0, io.EOF
		}
		n := copy(p, r.footer[r.pos:])
		r.pos += n
		return n, nil
	}

	if r.bufPos < r.bufLen {
		n := copy(p, r.buf[r.bufPos:r.bufLen])
		r.bufPos += n
		return n, nil
	}

	r.bufPos = 0
	r.bufLen = 0

	n, err := r.body.Read(r.buf)
	if n > 0 {
		r.bufLen = n

		chunk := r.buf[:n]
		sum := sha256.Sum256(chunk)

		r.hashes = append(r.hashes, HashWithLength{Hash: sum[:], Length: len(chunk)})
		r.total += int64(n)

		written := copy(p, chunk)
		r.bufPos = written
		return written, nil
	}
	if err == io.EOF {
		r.eof = true
		return r.Read(p)
	}
	return n, err
}

func (r *FooterReader) Close() error { return r.body.Close() }

// FooterAppendingReader returns a reader that appends a footer to the body.
func FooterAppendingReader(body io.ReadCloser, opt FooterOptions) (*FooterReader, error) {
	return &FooterReader{
		body:      body,
		chunkSize: opt.ChunkSize,
		buf:       make([]byte, opt.ChunkSize),
		signer:    opt.EcdsaSigner,
	}, nil
}

func createFooter(hashes []HashWithLength, total int64, signer *ecdsaSigner) ([]byte, *ValidatorPayload, error) {
	const footerVersion byte = 1
	var buf bytes.Buffer

	// Write magic bytes
	buf.Write(shared.MagicBytes)

	// Prepare signature input: version + sha256(all hashes) + sizeBytes
	buf.WriteByte(footerVersion)
	hasher := sha256.New()
	for _, h := range hashes {
		hasher.Write(h.Hash)
	}
	hashesDigest := hasher.Sum(nil)
	buf.Write(hashesDigest)

	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(total))
	buf.Write(sizeBytes)

	// Signature is over (hashesDigest + sizeBytes)
	sigInput := append(hashesDigest, sizeBytes...)

	// sigInput will be hashed inside the method
	sig, err := signer.signBytesCompact(sigInput[:])
	if err != nil {
		return nil, nil, err
	}

	buf.Write(sig)

	validatorPayload := &ValidatorPayload{
		Signature: sig,
		TotalSize: total,
		Hashes:    hashes,
	}

	return buf.Bytes(), validatorPayload, nil
}
