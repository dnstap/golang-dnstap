package dnstap

import (
	"io"
	"time"

	framestream "github.com/farsightsec/golang-framestream"
	"github.com/golang/protobuf/proto"
)

// A Decoder reads and parses Dnstap messages from an io.Reader
type Decoder struct {
	buf []byte
	r   *Reader
}

// DecoderOptions specifies configuration for the Decoder
type DecoderOptions struct {
	// If Bidirectional is true, the underlying io.Reader must also
	// satisfy io.Writer, and the dnstap Decoder will use the bidirectional
	// Frame Streams protocol.
	Bidirectional bool
	// Timeout sets the Read and Write timeout for the Decoder. This is
	// only in effect if the underlying io.Writer is a net.Conn.
	Timeout time.Duration
	// MaxPayloadSize gives the maximum acceptable encoded Dnstap message
	// for the Decoder. Messages larger than this size will be discarded,
	// and Decode() will return framestream.ErrDataFrameTooLarge.
	//
	// Subsequent calls to Decode() may succeed after a Decode() call
	// returns framestream.ErrDataFrameTooLarge.
	MaxPayloadSize uint32
}

// NewDecoder creates a Decoder with the underlying reader and options
func NewDecoder(r io.Reader, opt *DecoderOptions) (*Decoder, error) {
	dr, err := NewReader(r, &ReaderOptions{
		Bidirectional: opt.Bidirectional,
		Timeout:       opt.Timeout,
	})
	if err != nil {
		return nil, err
	}
	maxPayloadSize := opt.MaxPayloadSize
	if maxPayloadSize == 0 {
		maxPayloadSize = MaxPayloadSize
	}
	return &Decoder{
		buf: make([]byte, maxPayloadSize),
		r:   dr,
	}, nil
}

// Decode reads and parses a Dnstap message from the Decoder's Reader
func (d *Decoder) Decode(m *Dnstap) error {
	for {
		n, err := d.r.Read(d.buf)

		switch err {
		case framestream.ErrDataFrameTooLarge:
			continue
		case nil:
			break
		default:
			return err
		}

		return proto.Unmarshal(d.buf[:n], m)
	}
}
