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

import "log"
import "io"
import "os"

import framestream "github.com/farsightsec/golang-framestream"

var FSContentType = []byte("protobuf:dnstap.Dnstap")

type Reader struct {
    Convert     func([]byte) ([]byte, bool)
    wait        chan int
    fsinput     *framestream.Decoder
}

func NewReader(input io.Reader) (r *Reader, err error) {
    r = new(Reader)
    decoderOptions := framestream.DecoderOptions{
        ContentType: FSContentType,
    }
    r.fsinput, err = framestream.NewDecoder(input, &decoderOptions)
    if err != nil {
        return
    }
    r.wait = make(chan int)
    return
}

func NewReaderFromFilename(fname string) (r *Reader, err error) {
    input, err := os.Open(fname)
    if err != nil {
        return nil, err
    }
    r, err = NewReader(input)
    return
}

func (r *Reader) ReadInto(output chan []byte) {
    for {
        buf, err := r.fsinput.Decode()
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
            newbuf := make([]byte, len(buf))
            copy(newbuf, buf)
            output <- buf
        }
    }
    close(r.wait)
}

func (r *Reader) Wait() {
    <-r.wait
}
