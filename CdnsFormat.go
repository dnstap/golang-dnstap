/*
 * Copyright (c) 2013-2017 by Farsight Security, Inc and AFNIC
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

/* The C-DNS output was written by Stephane Bortzmeyer
/* <bortzmeyer@nic.fr> with help from Jim Hague <jim@sinodun.com>. It
/* follows the Internet-Draft
/* draft-ietf-dnsop-dns-capture-format-03. It is far from optimized:
/* most important, it creates one block for every request, thus
/* defeating the whole point of C-DNS (compression). Consider it as a
/* Proof-of-Concept. */

package dnstap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/miekg/dns"
)

var (
	first bool = true
)

func cborByteString(s []byte) []byte {
	var (
		r bytes.Buffer
	)
	if len(s) <= 23 {
		r.WriteByte(64 + byte(len(s))) // 64 = Major type 2
	} else {
		if len(s) > 65535 {
			fmt.Fprintf(os.Stderr, "Big byte strings not yet supported TODO\n")
			os.Exit(1)
		}
		if len(s) <= 255 {
			r.WriteByte(64 + 24) // 64 = Major type 2	, 24 = additional byte
			r.WriteByte(byte(len(s)))
		} else {
			tmp := make([]byte, 2)
			r.WriteByte(64 + 25)
			binary.BigEndian.PutUint16(tmp, uint16(len(s)))
			r.Write(tmp)
		}
	}
	r.Write(s)
	return r.Bytes()
}

func cborString(s string) []byte {
	var (
		r bytes.Buffer
	)
	if len(s) <= 23 {
		r.WriteByte(96 + byte(len(s))) // 96 = Major type 3
	} else {
		if len(s) > 65535 {
			fmt.Fprintf(os.Stderr, "Big strings not yet supported TODO\n")
			os.Exit(1)
		}
		if len(s) <= 255 {
			r.WriteByte(96 + 24) // 96 = Major type 3	, 24 = additional byte
			r.WriteByte(byte(len(s)))
		} else {
			tmp := make([]byte, 2)
			r.WriteByte(96 + 25)
			binary.BigEndian.PutUint16(tmp, uint16(len(s)))
			r.Write(tmp)
		}
	}
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
			tmp = make([]byte, 4)
			r.WriteByte(0 + 26)
			binary.BigEndian.PutUint32(tmp, uint32(i))
			r.Write(tmp)
		} else {
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

func cborIndefMap() []byte {
	var (
		r bytes.Buffer
	)
	r.WriteByte(160 + 31) // 160 = Major type 4, 31 = indefinite
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
		msg             *dns.Msg
	)

	if first {
		s.Write(cborArray(3))
		// File type ID
		s.Write(cborString("C-DNS"))
		// Preamble
		s.Write(cborMap(4))
		//    Major version
		s.Write(cborInteger(0))
		s.Write(cborInteger(0))
		//    Minor version
		s.Write(cborInteger(1))
		s.Write(cborInteger(5))
		//    Generator ID
		s.Write(cborInteger(4))
		s.Write(cborString(fmt.Sprintf("Experimental dnstap client, IETF 99 hackathon, data from %s", dt.Version)))
		//    Host ID
		s.Write(cborInteger(5))
		s.Write(cborString(string(dt.Identity)))
		// Blocks
		s.Write(cborArrayIndef())
		first = false
	}

	if *dt.Type == Dnstap_MESSAGE {
		m := dt.Message
		// Write a block for each message.
		// TODO: buffer for a few blocks (quite complicated, needs indexing, breaks existing assumptions, etc)
		s.Write(cborMap(3))
		// Block preamble
		s.Write(cborInteger(0))
		s.Write(cborMap(1))
		s.Write(cborInteger(1))
		s.Write(cborArray(2))
		if m.QueryTimeSec != nil {
			s.Write(cborInteger(int(*m.QueryTimeSec)))
		} else {
			s.Write(cborInteger(0))
		}
		s.Write(cborInteger(0)) // TODO real microseconds
		// Block tables
		s.Write(cborInteger(2))
		s.Write(cborIndefMap())
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
		if m.QueryMessage != nil {
			msg = new(dns.Msg)
			err := msg.Unpack(m.QueryMessage)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot unpack a DNS query message: %s\n", err)
				os.Exit(1)
			}
		}
		s.Write(cborInteger(0))
		if m.QueryMessage != nil {
			s.Write(cborInteger(int(msg.Question[0].Qtype)))
		} else {
			s.Write(cborInteger(0))
		}
		s.Write(cborInteger(1))
		s.Write(cborInteger(1)) //  Class IN
		//   Name rdata
		s.Write(cborInteger(2))
		qname := make([]byte, 256)
		n := 0
		err := error(nil)
		if m.QueryMessage != nil {
			n, err = dns.PackDomainName(msg.Question[0].Name, qname, 0, nil, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot pack a domain name: %s\n", err)
				os.Exit(1)
			}
		} else {
			qname[0] = 0
			n = 0
		}
		if m.ResponseMessage != nil {
			msg = new(dns.Msg)
			err := msg.Unpack(m.ResponseMessage)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot unpack a DNS response message: %s\n", err)
				os.Exit(1)
			}
		}
		s.Write(cborArray(1))
		s.Write(cborByteString(qname[0:n]))
		//   Query sig
		s.Write(cborInteger(3))
		s.Write(cborArray(1))
		s.Write(cborIndefMap())
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
			s.Write(cborInteger(1 + 4)) // Bit 0 has-query, bit 2 has-question
		} else { // A response
			s.Write(cborInteger(2))
		}
		//      QR DNS flags
		s.Write(cborInteger(5))
		s.Write(cborInteger(0))
		// Query class type index
		s.Write(cborInteger(7))
		s.Write(cborInteger(1))
		if m.QueryMessage != nil {
			//     QD count
			s.Write(cborInteger(8))
			s.Write(cborInteger(len(msg.Question)))
		}
		s.Write(cborBreak())       // End of query signature
		if m.QueryMessage != nil { // Useless (used only if there are several questions. TODO try to drop it
			// Question list
			s.Write(cborInteger(4))
			s.Write(cborArray(1))
			s.Write(cborArray(1))
			s.Write(cborInteger(1))
			// Question RR
			s.Write(cborInteger(5))
			s.Write(cborArray(1))
			s.Write(cborMap(2))
			s.Write(cborInteger(0)) // Name
			s.Write(cborInteger(1))
			s.Write(cborInteger(1)) // Class/type
			s.Write(cborInteger(1))
		}
		s.Write(cborBreak()) // End of block tables
		// Queries/Responses
		s.Write(cborInteger(3))
		s.Write(cborArray(1))
		s.Write(cborIndefMap())
		//    Time
		s.Write(cborInteger(0)) // TODO real time
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
		//    Query name index
		s.Write(cborInteger(9))
		s.Write(cborInteger(1))
		s.Write(cborBreak())
		// End of block

	}
	return s.Bytes(), true
}

func CdnsFinish(dt *Dnstap) (out []byte, ok bool) {
	var s bytes.Buffer
	s.Write(cborBreak()) // End of the blocks array
	return s.Bytes(), true
}
