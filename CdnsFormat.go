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
		r bytes.Buffer
	)
	if i < 0 {
		fmt.Fprintf(os.Stderr, "Negative integers not yet supported TODO\n")
		os.Exit(1)
	}
	if i > 23 {
		fmt.Fprintf(os.Stderr, "Big integers not yet supported TODO\n")
		os.Exit(1)
	}
	r.WriteByte(0 + byte(i)) // 0 = Major type 0
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
		s     bytes.Buffer
		dummy []byte
	)

	dummy = make([]byte, 16)
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

	// Write a block for each message
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
	//    IP addresses
	s.Write(cborInteger(0))
	s.Write(cborArray(1))
	s.Write(cborByteString(dummy)) // TODO put the real IP address
	//   Class type
	s.Write(cborInteger(1))
	s.Write(cborArray(1))
	s.Write(cborMap(2))
	s.Write(cborInteger(0))
	s.Write(cborInteger(1)) // Class IN
	s.Write(cborInteger(1))
	s.Write(cborInteger(15)) // Type MX
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
	s.Write(cborInteger(1))
	//      Server port
	s.Write(cborInteger(1))
	s.Write(cborInteger(11)) // TODO real port
	//      Transport flags
	s.Write(cborInteger(2))
	s.Write(cborInteger(2)) // IPv6. TODO: use real ones
	//      QR sig flags
	s.Write(cborInteger(3))
	s.Write(cborInteger(0))
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
	s.Write(cborInteger(10)) // TODO put the real port
	//    Transaction ID
	s.Write(cborInteger(4))
	s.Write(cborInteger(6)) // TODO put the real ID
	//    Query signature index
	s.Write(cborInteger(5))
	s.Write(cborInteger(1))
	// End of block

	fmt.Fprintf(os.Stderr, "%d bytes emitted\n", len(s.Bytes()))
	return s.Bytes(), true
}

func CdnsFinish(dt *Dnstap) (out []byte, ok bool) {
	var s bytes.Buffer
	s.Write(cborBreak()) // End of the blocks array
	return s.Bytes(), true
}
