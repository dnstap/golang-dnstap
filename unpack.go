package dnstap

/*
    Copyright (c) 2013 by Internet Systems Consortium, Inc. ("ISC")

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
    OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import "bytes"
import "encoding/binary"
import "log"

import "code.google.com/p/goprotobuf/proto"

func Unpack(buf []byte) (dt *Dnstap, ok bool) {
    if len(buf) <= 6 {
        return nil, false
    }

    /* 4 bytes: length of payload ("DT" header + packed protobuf) */
    var len_dt uint32
    err := binary.Read(bytes.NewBuffer(buf[0:4]), binary.LittleEndian, &len_dt)
    if err != nil {
        return nil, false
    }
    if len_dt != uint32(len(buf) - 4) {
        log.Fatalf("Unpack: length mismatch: %u != %d\n", len_dt, len(buf) - 4)
        return nil, false
    }

    /* 2 bytes: "DT" header */
    if buf[4] != 'D' || buf[5] != 'T' {
        return nil, false
    }

    /* remaining bytes */
    dt = &Dnstap{}
    err = proto.Unmarshal(buf[6:len(buf)], dt)
    if err != nil {
        log.Fatalf("Unpack: proto.Unmarshal() failed: %s\n", err)
        return nil, false
    }

    return dt, true
}
