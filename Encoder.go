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
	"net"

	"github.com/golang/protobuf/proto"
)

// An Encoder serializes and writes Dnstap messages to an underlying
// io.Writer.
type Encoder struct {
	w *Writer
}

// NewEncoder creates an Encoder using the given io.Writer and options.
func NewEncoder(w io.Writer, opt *WriterOptions) (*Encoder, error) {
	ew, err := NewWriter(w, opt)
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

type SocketEncoder struct {
	w *SocketWriter
}

func NewSocketEncoder(addr net.Addr, opt *SocketWriterOptions) *SocketEncoder {
	return &SocketEncoder{
		w: NewSocketWriter(addr, opt),
	}
}

func (se *SocketEncoder) Encode(m *Dnstap) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}

	_, err = se.w.Write(b)
	return err
}
