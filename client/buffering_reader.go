package client

import (
	"bytes"
	"io"
)

type MaybeBufferingReader struct {
	io.Reader
	source io.ReadCloser
	buffer *bytes.Buffer
}

func NewMaybeBufferingReader(delegate io.ReadCloser, shouldBuffer bool) *MaybeBufferingReader {
	if !shouldBuffer || delegate == nil {
		return &MaybeBufferingReader{Reader: delegate, source: delegate}
	}

	buf := new(bytes.Buffer)
	return &MaybeBufferingReader{
		Reader: io.TeeReader(delegate, buf),
		source: delegate,
		buffer: buf,
	}
}

func (b *MaybeBufferingReader) Close() error {
	if b.source == nil {
		return nil
	}

	return b.source.Close()
}

func (b *MaybeBufferingReader) GetBufferedData() []byte {
	if b.buffer == nil {
		return nil
	}
	return b.buffer.Bytes()
}
