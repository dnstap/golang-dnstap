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

import "bufio"
import "bytes"
import "encoding/binary"
import "log"
import "io"
import "os"

type Reader struct {
    Convert     func([]byte) ([]byte, bool)
    wait        chan int
    input       *bufio.Reader
}

func NewReader(input io.Reader) (r *Reader) {
    r = new(Reader)
    r.input = bufio.NewReader(input)
    r.wait = make(chan int)
    return r
}

func NewReaderFromFilename(fname string) (r *Reader, err error) {
    input, err := os.Open(fname)
    if err != nil {
        return nil, err
    }
    return NewReader(input), nil
}

func (r *Reader) readBuf() (buf []byte, err error) {
    len_payload_packed, err := r.input.Peek(4)
    if err != nil {
        return nil, err
    }

    var len_payload uint32
    p := bytes.NewBuffer(len_payload_packed[0:])
    err = binary.Read(p, binary.LittleEndian, &len_payload)
    if err != nil {
        return nil, err
    }

    buf = make([]byte, len_payload + 4)
    n := 0
    for {
        nbytes, e := r.input.Read(buf[n:len(buf)])
        if nbytes == 0 || e != nil {
            return nil, e
        }
        n += nbytes
        if n == len(buf) {
            break
        }
    }

    return buf, nil
}

func (r *Reader) Read(output chan []byte) {
    for {
        buf, err := r.readBuf()
        if err != nil {
            if err != io.EOF {
                log.Printf("Read() failed: %s\n", err)
            }
            break
        }
        if r.Convert != nil {
            if newbuf, ok := r.Convert(buf); ok {
                output <- newbuf
            }
        } else {
            output <- buf
        }
    }
    close(r.wait)
}

func (r *Reader) Wait() {
    <-r.wait
}
