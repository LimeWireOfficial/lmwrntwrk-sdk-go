package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"log/slog"
)

type FixedLengthValidatingReader struct {
	inputReader              io.Reader
	pubKey                   []byte
	footerSize               int
	chunkSize                int
	ringBuffer               *RingBuffer
	internalReadBuffer       []byte
	eofDetected              bool
	hashes                   []HashWithLength
	totalBytes               int64
	hasher                   hash.Hash
	bytesInHasher            int
	isRequestRecordingNeeded bool
	requestWithoutFooter     bytes.Buffer
}

func NewFixedLengthValidatingReader(inputReader io.Reader, pubKey []byte, footerSize int, chunkSize int, isRequestRecordingNeeded bool) *FixedLengthValidatingReader {
	return &FixedLengthValidatingReader{
		inputReader:              inputReader,
		footerSize:               footerSize,
		pubKey:                   pubKey,
		chunkSize:                chunkSize,
		internalReadBuffer:       make([]byte, 32*1024),
		eofDetected:              false,
		ringBuffer:               NewRing(footerSize),
		hasher:                   sha256.New(),
		isRequestRecordingNeeded: isRequestRecordingNeeded,
	}
}

func (v *FixedLengthValidatingReader) Read(output []byte) (int, error) {
	// if footer size is 0 this class just acts as proxy
	if v.footerSize == 0 {
		n, err := v.inputReader.Read(output)
		return n, err
	}

	if v.eofDetected {
		return 0, io.EOF
	}

	// make sure that on the first read we fill up the whole ringBuffer + read enough bytes to potentially fill the output array.
	// once the RingBuffer is filled we only need to read as many bytes as we then emit & hash
	maxRead := min(len(output)+(v.footerSize-v.ringBuffer.Len()), len(v.internalReadBuffer))

	bytesRead, err := v.inputReader.Read(v.internalReadBuffer[:maxRead])
	if bytesRead > 0 {
		out := output[:0]

		for i := 0; i < bytesRead; i++ {
			currentByte := v.internalReadBuffer[i]

			// data is pushed into the RingBuffer, which has the same size as the defined footer length.
			// if it is full it will evict the first added byte, meaning that we are sure it won't be part of the footer.
			// that means we can safely continue with that data, hashing & pushing it downstream
			if ev, ok := v.ringBuffer.Push(currentByte); ok {
				if len(out) < len(output) {
					out = append(out, ev)
				} else {
					v.feedHash(out)
					return len(out), nil
				}
			}
		}

		if len(out) > 0 {
			v.feedHash(out)
		}

		if err == io.EOF {
			v.finishAtEOF()
			validateErr := v.ValidateFooter(v.pubKey)

			if validateErr != nil {
				return 0, validateErr
			}

			if len(out) > 0 {
				return len(out), nil
			}

			return 0, io.EOF
		}
		return len(out), nil
	}

	if err == io.EOF {
		v.finishAtEOF()
		validateErr := v.ValidateFooter(v.pubKey)
		if validateErr != nil {
			return 0, validateErr
		}

		return 0, io.EOF
	}

	if err != nil {
		slog.Info("an error happened, I guess here we need to do some magic", "err", err)
		return 0, err
	}

	return 0, nil
}

func (v *FixedLengthValidatingReader) GetFooterBytes() []byte {
	if !v.eofDetected {
		return nil
	}

	return v.ringBuffer.Bytes()
}

func (v *FixedLengthValidatingReader) FooterData() *Footer {
	if !v.eofDetected {
		return nil
	}

	return NewFooter(v.ringBuffer.Bytes())
}

func (v *FixedLengthValidatingReader) finishAtEOF() {
	v.eofDetected = true

	// in case we detect EOF we can build the final hash with the leftover data
	if v.bytesInHasher > 0 {
		sum := v.hasher.Sum(nil)
		v.hashes = append(v.hashes, HashWithLength{Hash: sum[:], Length: v.bytesInHasher})
		v.hasher.Reset()
		v.bytesInHasher = 0
	}
}

func (v *FixedLengthValidatingReader) feedHash(chunk []byte) {
	v.totalBytes += int64(len(chunk))

	if v.isRequestRecordingNeeded {
		v.requestWithoutFooter.Write(chunk)
	}

	off := 0
	for off < len(chunk) {
		space := v.chunkSize - v.bytesInHasher
		if space > len(chunk)-off {
			space = len(chunk) - off
		}

		v.hasher.Write(chunk[off : off+space])
		v.bytesInHasher += space
		off += space

		if v.bytesInHasher == v.chunkSize {
			sum := v.hasher.Sum(nil)
			v.hasher.Reset()
			v.bytesInHasher = 0
			v.hashes = append(v.hashes, HashWithLength{Hash: sum[:], Length: len(chunk)})
		}
	}
}

func (v *FixedLengthValidatingReader) ValidateFooter(expectedKey []byte) error {
	footer := v.FooterData()
	return footer.Validate(expectedKey, v.totalBytes, v.hashes)
}

func (v *FixedLengthValidatingReader) GetFooterSignatureBytes() []byte {
	footer := v.FooterData()
	return footer.sig
}

func (v *FixedLengthValidatingReader) GetHashes() []HashWithLength {
	return v.hashes
}

func (v *FixedLengthValidatingReader) GetTotalBytes() int64 {
	return v.totalBytes
}

func (v *FixedLengthValidatingReader) GetRequestWithoutFooterBase64() string {
	return base64.StdEncoding.EncodeToString(v.GetFooterBytes())
}

func (v *FixedLengthValidatingReader) GetRequestWithoutFooter() string {
	return v.requestWithoutFooter.String()
}

func (v *FixedLengthValidatingReader) Close() error {
	if closer, ok := v.inputReader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
