/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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
	"log"
	"net"
	"os"
	"time"

	"github.com/farsightsec/golang-framestream"
)

const tcpDialTimeout = 5
const writeTimeout = 5

type FrameStreamOutput struct {
	outputChannel chan []byte
	wait          chan bool
	enc           *framestream.Encoder
}

func NewFrameStreamOutput(w io.Writer, bi bool) (o *FrameStreamOutput, err error) {
	o = new(FrameStreamOutput)
	o.outputChannel = make(chan []byte, outputChannelSize)
	o.enc, err = framestream.NewEncoder(w, &framestream.EncoderOptions{ContentType: FSContentType, Bidirectional: bi})
	o.enc.Flush()
	if err != nil {
		return
	}
	o.wait = make(chan bool)
	return
}

func NewFrameStreamOutputFromFilename(fname string) (o *FrameStreamOutput, err error) {
	if fname == "" || fname == "-" {
		return NewFrameStreamOutput(os.Stdout, false)
	}
	w, err := os.Create(fname)
	if err != nil {
		return
	}
	return NewFrameStreamOutput(w, false)
}

func NewFrameStreamOutputFromTCP(addr string) (o *FrameStreamOutput, err error) {
	conn, err := net.DialTimeout("tcp", addr, tcpDialTimeout*time.Second)
	if err != nil {
		return
	}

	return NewFrameStreamOutput(conn, true)
}

func (o *FrameStreamOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}

func (o *FrameStreamOutput) RunOutputLoop() {
	for frame := range o.outputChannel {
		ch := make(chan error)
		go func() {
			if _, err := o.enc.Write(frame); err != nil {
				ch <- err

			}
			ch <- nil
		}()
		timer := time.NewTimer(writeTimeout * time.Second)
		select {
		case err := <-ch:
			timer.Stop()
			if err != nil {
				log.Fatalf("framestream.Encoder.Write() failed: %s\n", err)
				break
			}
		case <-timer.C:
			log.Fatalf("Timeout writing to FrameStreamOutput")
		}
	}
	close(o.wait)
}

func (o *FrameStreamOutput) Close() {
	close(o.outputChannel)
	<-o.wait
	o.enc.Flush()
	o.enc.Close()
}
