package shared

import (
	"golang.org/x/crypto/sha3"
)

func AddressFromUncompressed(uncompressed []byte) []byte {
	switch len(uncompressed) {
	case 65:
		if uncompressed[0] != 0x04 {
			return nil
		}
		uncompressed = uncompressed[1:] // drop prefix, keep X||Y (64 bytes)
	case 64:
		// already X||Y
	default:
		return nil
	}

	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[:]) // X||Y
	sum := h.Sum(nil)
	var addr [20]byte
	copy(addr[:], sum[12:])
	return addr[:]
}
