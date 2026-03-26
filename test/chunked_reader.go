package footer

import "io"

type ChunkedReader struct {
	data       []byte
	chunkSizes []int
	index      int
}

func (sr *ChunkedReader) Read(p []byte) (int, error) {
	if sr.index >= len(sr.data) {
		return 0, io.EOF
	}

	// Use the current chunk size to determine how many bytes to return
	size := sr.chunkSizes[0]
	if len(sr.chunkSizes) > 1 {
		sr.chunkSizes = sr.chunkSizes[1:] // Consume chunk size for this call
	}

	if sr.index+size > len(sr.data) {
		size = len(sr.data) - sr.index
	}

	n := copy(p, sr.data[sr.index:sr.index+size])
	sr.index += n
	return n, nil
}

func NewChunkedReader(data []byte, chunkSizes []int) *ChunkedReader {
	return &ChunkedReader{
		data:       data,
		chunkSizes: chunkSizes,
		index:      0,
	}
}
