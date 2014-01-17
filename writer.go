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

import "bufio"
import "io"
import "log"
import "os"

type Writer struct {
    Unbuffered  bool
    wait        chan bool
    output      *bufio.Writer
}

func NewWriter(output io.Writer) (w *Writer) {
    w = new(Writer)
    w.output = bufio.NewWriter(output)
    w.wait = make(chan bool)
    return w
}

func NewWriterFromFilename(fname string) (w *Writer, e error) {
    if fname == "" || fname == "-" {
        return NewWriter(os.Stdout), nil
    }
    output, err := os.Create(fname)
    if err != nil {
        return nil, err
    }
    return NewWriter(output), nil
}

func (w *Writer) Write(channel chan []byte) {
    for buf := range channel {
        if _, err := w.output.Write(buf); err != nil {
            log.Fatalf("Write() failed: %s\n", err)
            break
        }
        if w.Unbuffered {
            w.output.Flush()
        }
    }
    close(w.wait)
}

func (w *Writer) Wait() {
    <-w.wait
    w.output.Flush()
}
