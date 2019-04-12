/*
 * Copyright (c) 2019 by Farsight Security, Inc.
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
	"log"
	"net"
	"time"

	"github.com/farsightsec/golang-framestream"
)

type FrameStreamSockOutput struct {
	outputChannel chan []byte
	address       net.Addr
	wait          chan bool
	dialer        *net.Dialer
	timeout       time.Duration
	retry         time.Duration
}

func NewFrameStreamSockOutput(address net.Addr) (*FrameStreamSockOutput, error) {
	return &FrameStreamSockOutput{
		outputChannel: make(chan []byte, outputChannelSize),
		address:       address,
		wait:          make(chan bool),
		retry:         10 * time.Second,
		dialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (o *FrameStreamSockOutput) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

func (o *FrameStreamSockOutput) SetRetryInterval(retry time.Duration) {
	o.retry = retry
}

func (o *FrameStreamSockOutput) SetDialer(dialer *net.Dialer) {
	o.dialer = dialer
}

func (o *FrameStreamSockOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}

func (o *FrameStreamSockOutput) RunOutputLoop() {
	var enc *framestream.Encoder
	var c net.Conn
	var err error

	for frame := range o.outputChannel {
		for enc == nil {
			c, err = o.dialer.Dial(o.address.Network(), o.address.String())
			if err != nil {
				log.Printf("Dial failed: %v", err)
				c = nil
				time.Sleep(o.retry)
				continue
			}
			eopt := &framestream.EncoderOptions{
				ContentType:   FSContentType,
				Bidirectional: true,
				Timeout:       o.timeout,
			}
			enc, err = framestream.NewEncoder(c, eopt)
			if err != nil {
				log.Printf("framestream.NewEncoder() failed: %v\n", err)
				if c != nil {
					c.Close()
					c = nil
				}
				enc = nil
				continue
			}
		}

		if _, err := enc.Write(frame); err != nil {
			log.Printf("framestream.Encoder.Write() failed: %s\n", err)
			enc.Close()
			enc = nil
			c.Close()
			c = nil
		}
		if err := enc.Flush(); err != nil {
			log.Printf("framestream.Encoder.Flush() failed: %s\n", err)
			enc.Close()
			enc = nil
			c.Close()
			c = nil
		}
	}
	if enc != nil {
		enc.Close()
		c.Close()
	}
	close(o.wait)
}

func (o *FrameStreamSockOutput) Close() {
	close(o.outputChannel)
	<-o.wait
}
