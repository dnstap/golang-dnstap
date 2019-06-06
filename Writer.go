package dnstap

import (
	"io"
	"time"

	framestream "github.com/farsightsec/golang-framestream"
)

// A Writer writes Dnstap frames to an underlying io.Writer
type Writer struct {
	*framestream.Writer
}

// WriterOptions specifies configuration for the Writer
type WriterOptions struct {
	// If Bidirectional is true, the underlying io.Writer must also
	// satisfy io.Reader, and the dnstap Writer will use the bidirectional
	// Frame Streams protocol.
	Bidirectional bool
	// Timeout sets the write timeout for data and control messages and the
	// read timeout for handshake responses on the underlying Writer. Timeout
	// is only effective if the underlying Writer is a net.Conn.
	Timeout time.Duration
}

// NewWriter creates a Writer using the given io.Writer and options.
func NewWriter(w io.Writer, opt *WriterOptions) (*Writer, error) {
	if opt == nil {
		opt = &WriterOptions{}
	}
	fw, err := framestream.NewWriter(w,
		&framestream.WriterOptions{
			ContentTypes:  [][]byte{FSContentType},
			Timeout:       opt.Timeout,
			Bidirectional: opt.Bidirectional,
		})
	if err != nil {
		return nil, err
	}
	return &Writer{fw}, nil
}
