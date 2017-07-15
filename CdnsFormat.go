/*
 * Copyright (c) 2013-2014 by Farsight Security, Inc.
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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

var (
	first bool = true
)

func cborByteString(s []byte) []byte {
	var (
		r bytes.Buffer
	)
	if len(s) > 23 {
		fmt.Fprintf(os.Stderr, "Long byte strings not yet supported TODO\n")
		os.Exit(1)
	}
	r.WriteByte(64 + byte(len(s))) // 64 = Major type 2
	r.Write(s)
	return r.Bytes()
}

func cborString(s string) []byte {
	var (
		r bytes.Buffer
	)
	if len(s) > 23 {
		fmt.Fprintf(os.Stderr, "Long strings not yet supported TODO\n")
		os.Exit(1)
	}
	r.WriteByte(96 + byte(len(s))) // 96 = Major type 3
	r.WriteString(s)
	return r.Bytes()
}

func cborInteger(i int) []byte {
	var (
		r   bytes.Buffer
		tmp []byte
	)
	if i < 0 {
		fmt.Fprintf(os.Stderr, "Negative integers not yet supported TODO\n")
		os.Exit(1)
	}
	if i <= 23 {
		r.WriteByte(0 + byte(i)) // 0 = Major type 0
	} else {
		if i > 65535 {
			fmt.Fprintf(os.Stderr, "Big integers not yet supported TODO\n")
			os.Exit(1)
		}
		if i <= 255 {
			r.WriteByte(0 + 24) // 0 = Major type 0	, 24 = additional byte
			r.WriteByte(byte(i))
		} else {
			tmp = make([]byte, 2)
			r.WriteByte(0 + 25)
			binary.BigEndian.PutUint16(tmp, uint16(i))
			r.Write(tmp)
		}
	}
	return r.Bytes()
}

func cborArray(size uint) []byte {
	var (
		r bytes.Buffer
	)
	if size > 23 {
		fmt.Fprintf(os.Stderr, "Big arrays not yet supported TODO\n")
		os.Exit(1)
	}
	r.WriteByte(128 + byte(size)) // 128 = Major type 3
	return r.Bytes()
}

func cborArrayIndef() []byte {
	var (
		r bytes.Buffer
	)
	r.WriteByte(128 + 31) // 128 = Major type 3, 31 = indefinite
	return r.Bytes()
}

// TODO indefinite length maps
func cborMap(size uint) []byte {
	var (
		r bytes.Buffer
	)
	if size > 23 {
		fmt.Fprintf(os.Stderr, "Big maps not yet supported TODO\n")
		os.Exit(1)
	}
	r.WriteByte(160 + byte(size)) // 160 = Major type 4
	return r.Bytes()
}

func cborBreak() []byte {
	var (
		r bytes.Buffer
	)
	r.WriteByte(224 + 31) // 224 = Major type 7 + 31 = mandatory for break
	return r.Bytes()
}

func CdnsFormat(dt *Dnstap) (out []byte, ok bool) {
	var (
		s               bytes.Buffer
		clientAddr      []byte = nil
		serverAddr      []byte = nil
		dummy           []byte = nil
		sourcePort      uint32 = 0
		destinationPort uint32 = 0
	)

	// TODO : put dt.Type, dt.Identity and  dt.Version somewhere
	if first {
		s.Write(cborArray(3))
		// File type ID
		s.Write(cborString("C-DNS"))
		// Preamble
		s.Write(cborMap(3))
		//    Major version
		s.Write(cborInteger(0))
		s.Write(cborInteger(0))
		//    Minor version
		s.Write(cborInteger(1))
		s.Write(cborInteger(5))
		//    Generator ID
		s.Write(cborInteger(4))
		s.Write(cborString("IETF 99 hackathon"))
		// Blocks
		s.Write(cborArrayIndef())
		first = false
	}

	if *dt.Type == Dnstap_MESSAGE {
		m := dt.Message
		// Write a block for each message. TODO: buffer for a few blocks
		s.Write(cborMap(3))
		// Block preamble
		s.Write(cborInteger(0))
		s.Write(cborMap(1))
		s.Write(cborInteger(1))
		s.Write(cborArray(2))
		s.Write(cborInteger(0)) // TODO real seconds
		s.Write(cborInteger(0)) // TODO real microseconds
		// Block tables
		s.Write(cborInteger(2))
		s.Write(cborMap(4))
		//    IP addresses.
		s.Write(cborInteger(0))
		clientAddr = m.QueryAddress
		serverAddr = m.ResponseAddress
		if m.QueryPort != nil {
			sourcePort = *m.QueryPort
		}
		if m.ResponsePort != nil {
			destinationPort = *m.ResponsePort
		}
		if clientAddr == nil && serverAddr == nil {
			fmt.Fprintf(os.Stderr, "No IP addresses at all in the message, I give in\n")
			os.Exit(1)
		}
		s.Write(cborArray(2))
		if clientAddr != nil && serverAddr != nil {
			s.Write(cborByteString(clientAddr))
			s.Write(cborByteString(serverAddr))
		} else {
			switch *m.SocketFamily {
			case SocketFamily_INET:
				dummy = make([]byte, 4)
			case SocketFamily_INET6:
				dummy = make([]byte, 16)
			default:
				fmt.Fprintf(os.Stderr, "Unknown socket family %d\n", *m.SocketFamily)
				os.Exit(1)
			}
			if clientAddr == nil {
				s.Write(cborByteString(dummy))
				s.Write(cborByteString(serverAddr))
			} else {
				s.Write(cborByteString(clientAddr))
				s.Write(cborByteString(dummy))
			}
		}
		//   Class type
		s.Write(cborInteger(1))
		s.Write(cborArray(1))
		s.Write(cborMap(2))
		s.Write(cborInteger(0))
		s.Write(cborInteger(15)) // Type MX
		s.Write(cborInteger(1))
		s.Write(cborInteger(1)) //  Class IN
		//   Name rdata
		s.Write(cborInteger(2))
		s.Write(cborArray(1))
		b := make([]byte, 5)
		b[0] = 3
		b[1] = 'c'
		b[2] = 'o'
		b[3] = 'm'
		b[4] = 0
		s.Write(cborByteString(b)) // TODO real data
		//   Query sig
		s.Write(cborInteger(3))
		s.Write(cborArray(1))
		s.Write(cborMap(5))
		//      Server address index
		s.Write(cborInteger(0))
		s.Write(cborInteger(2))
		//      Server port
		s.Write(cborInteger(1))
		s.Write(cborInteger(int(destinationPort)))
		//      Transport flags
		s.Write(cborInteger(2))
		switch *m.SocketFamily {
		case SocketFamily_INET:
			s.Write(cborInteger(0))
		case SocketFamily_INET6:
			s.Write(cborInteger(2))
		default:
			fmt.Fprintf(os.Stderr, "Unknown socket family %d\n", *m.SocketFamily)
			os.Exit(1)
		}
		//      QR sig flags
		s.Write(cborInteger(3))
		if m.QueryMessage != nil {
			s.Write(cborInteger(1))
		} else { // A response
			s.Write(cborInteger(2))
		}
		//      QR DNS flags
		s.Write(cborInteger(5))
		s.Write(cborInteger(0))
		// End of block tables
		// Queries/Responses
		s.Write(cborInteger(3))
		s.Write(cborArray(1))
		s.Write(cborMap(5))
		//    Time
		s.Write(cborInteger(0))
		s.Write(cborInteger(0))
		//    Client address index
		s.Write(cborInteger(2))
		s.Write(cborInteger(1))
		//    Client port
		s.Write(cborInteger(3))
		s.Write(cborInteger(int(sourcePort)))
		//    Transaction ID
		s.Write(cborInteger(4))
		s.Write(cborInteger(666)) // TODO put the real ID
		//    Query signature index
		s.Write(cborInteger(5))
		s.Write(cborInteger(1))
		// End of block

		fmt.Fprintf(os.Stderr, "%d bytes emitted\n", len(s.Bytes()))
	}
	return s.Bytes(), true
}

func CdnsFinish(dt *Dnstap) (out []byte, ok bool) {
	var s bytes.Buffer
	s.Write(cborBreak()) // End of the blocks array
	return s.Bytes(), true
}
