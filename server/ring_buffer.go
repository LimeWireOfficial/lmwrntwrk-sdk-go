package server

type RingBuffer struct {
	buf    []byte
	head   int // next write position
	filled int
}

func NewRing(n int) *RingBuffer {
	if n < 0 {
		panic("n must be >= 0")
	}
	return &RingBuffer{buf: make([]byte, n)}
}

func (r *RingBuffer) Cap() int { return len(r.buf) }
func (r *RingBuffer) Len() int { return r.filled }

// Push adds b. If the ring was full, it returns (evicted, true). Otherwise (_, false).
func (r *RingBuffer) Push(b byte) (byte, bool) {
	if len(r.buf) == 0 {
		return 0, false
	}
	if r.filled < len(r.buf) {
		r.buf[r.head] = b
		r.head = (r.head + 1) % len(r.buf)
		r.filled++
		return 0, false
	}
	ev := r.buf[r.head]
	r.buf[r.head] = b
	r.head = (r.head + 1) % len(r.buf)
	return ev, true
}

// Bytes returns the contents in order from oldest to newest.
func (r *RingBuffer) Bytes() []byte {
	n := r.filled
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	start := (r.head - n) % len(r.buf)
	if start < 0 {
		start += len(r.buf)
	}
	if start+n <= len(r.buf) {
		copy(out, r.buf[start:start+n])
	} else {
		first := len(r.buf) - start
		copy(out, r.buf[start:])
		copy(out[first:], r.buf[:n-first])
	}
	return out
}
