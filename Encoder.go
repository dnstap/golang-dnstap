package dnstap

import (
	"io"
	"time"

	"github.com/golang/protobuf/proto"
)

// A dnstap Encoder serializes and writes Dnstap messages to an underlying
// io.Writer.
type Encoder struct {
	w *Writer
}

// EncoderOptions specifies configuration for the Encoder
type EncoderOptions struct {
	// If Bidirectional is true, the underlying io.Writer must also
	// satisfy io.Reader, and the dnstap Encoder will use the bidirectional
	// Frame Streams protocol.
	Bidirectional bool
	// Timeout sets the Read and Write timeout for the Encoder. This is
	// only in effect if the underlying io.Writer is a net.Conn.
	Timeout time.Duration
}

// NewEncoder creates an Encoder using the given io.Writer and options.
func NewEncoder(w io.Writer, opt *EncoderOptions) (*Encoder, error) {
	ew, err := NewWriter(w, &WriterOptions{
		Bidirectional: opt.Bidirectional,
		Timeout:       opt.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &Encoder{w: ew}, nil
}

// Encode serializes and writes the Dnstap message me to the encoder's
// Writer.
func (e *Encoder) Encode(m *Dnstap) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}

	_, err = e.w.Write(b)
	return err
}
