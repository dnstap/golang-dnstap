package dnstap

/*
    Copyright (c) 2013-2014 by Farsight Security, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
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
