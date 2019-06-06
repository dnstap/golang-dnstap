package dnstap

import (
	"io"
	"time"

	framestream "github.com/farsightsec/golang-framestream"
)

// A Reader reads Dnstap frames from an underlying io.Reader
type Reader struct {
	*framestream.Reader
}

// ReaderOptions specifies configuration for the Reader.
type ReaderOptions struct {
	// If Bidirectional is true, the underlying io.Reader must also
	// satisfy io.Writer, and the dnstap Reader will use the bidirectional
	// Frame Streams protocol.
	Bidirectional bool
	// Timeout sets the timeout for reading the initial handshake and
	// writing response control messages to the underlying Reader. Timeout
	// is only effective if the underlying Reader is a net.Conn.
	Timeout time.Duration
}

// NewReader creates a Reader using the given io.Reader and options.
func NewReader(r io.Reader, opt *ReaderOptions) (*Reader, error) {
	if opt == nil {
		opt = &ReaderOptions{}
	}
	fr, err := framestream.NewReader(r,
		&framestream.ReaderOptions{
			ContentTypes:  [][]byte{FSContentType},
			Timeout:       opt.Timeout,
			Bidirectional: opt.Bidirectional,
		})
	if err != nil {
		return nil, err
	}
	return &Reader{fr}, nil
}
