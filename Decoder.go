/*
 * Copyright (c) 2019 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
