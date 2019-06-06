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

	"github.com/golang/protobuf/proto"
)

// An Encoder serializes and writes Dnstap messages to an underlying
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

// Encode serializes and writes the Dnstap message m to the encoder's
// Writer.
func (e *Encoder) Encode(m *Dnstap) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}

	_, err = e.w.Write(b)
	return err
}
