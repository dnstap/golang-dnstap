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
