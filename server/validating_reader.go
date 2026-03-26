package server

type HashWithLength struct {
	Hash   []byte
	Length int
}

type ValidatingReader interface {
	GetFooterBytes() []byte
	GetFooterSignatureBytes() []byte
	GetHashes() []HashWithLength
	GetTotalBytes() int64
	GetRequestWithoutFooter() string
}
