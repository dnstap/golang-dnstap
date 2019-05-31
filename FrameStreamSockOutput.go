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
	"sync"
	"log"
	"net"
	"time"

	"github.com/farsightsec/golang-framestream"
)

// A FrameStreamSockOutput manages a socket connection and sends dnstap
// data over a framestream connection on that socket.
type FrameStreamSockOutput struct {
	outputChannel chan []byte
	address       net.Addr
	wait          chan bool
	dialer        *net.Dialer
	timeout       time.Duration
	retry         time.Duration
	flushTimeout  time.Duration
}

// NewFrameStreamSockOutput creates a FrameStreamSockOutput manaaging a
// connection to the given address.
func NewFrameStreamSockOutput(address net.Addr) (*FrameStreamSockOutput, error) {
	return &FrameStreamSockOutput{
		outputChannel: make(chan []byte, outputChannelSize),
		address:       address,
		wait:          make(chan bool),
		retry:         10 * time.Second,
		flushTimeout:  5 * time.Second,
		dialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// SetTimeout sets the write timeout for data and control messages and the
// read timeout for handshake responses on the FrameStreamSockOutput's
// connection. The default timeout is zero, for no timeout.
func (o *FrameStreamSockOutput) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// SetFlushTimeout sets the maximum time data will be kept in the output
// buffer.
//
// The default flush timeout is five seconds.
func (o *FrameStreamSockOutput) SetFlushTimeout(timeout time.Duration) {
	o.flushTimeout = timeout
}

// SetRetryInterval specifies how long the FrameStreamSockOutput will wait
// before re-establishing a failed connection. The default retry interval
// is 10 seconds.
func (o *FrameStreamSockOutput) SetRetryInterval(retry time.Duration) {
	o.retry = retry
}

// SetDialer replaces the default net.Dialer for re-establishing the
// the FrameStreamSockOutput connection. This can be used to set the
// timeout for connection establishment and enable keepalives
// new connections.
//
// FrameStreamSockOutput uses a default dialer with a 30 second
// timeout.
func (o *FrameStreamSockOutput) SetDialer(dialer *net.Dialer) {
	o.dialer = dialer
}

// GetOutputChannel returns the channel on which the
// FrameStreamSockOutput accepts data.
//
// GetOutputChannel satisifes the dnstap Output interface.
func (o *FrameStreamSockOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}

type timedEnc struct {
	mutex     sync.Mutex
	enc      *framestream.Encoder
	lastwrite int64 // from nanotime()
	stop      bool
}

func (t *timedEnc) RunTimeoutLoop(timeout time.Duration) {
	for {
		time.Sleep(timeout)

		t.mutex.Lock()
		switch {
		case t.stop:
			return
		case t.enc == nil || t.lastwrite == 0:
			// nothing to do, skip
		case nanotime() >= t.lastwrite + int64(timeout):
			t.enc.Flush()
			t.lastwrite = 0
		}
		t.mutex.Unlock()
	}
}

func (t *timedEnc) Stop() {
	t.mutex.Lock()
	if t.enc != nil {
		t.enc.Flush()
		t.enc.Close()
		t.enc = nil
	}
	t.stop = true
	t.mutex.Unlock()
}

// RunOutputLoop reads data from the output channel and sends it over
// a connections to the FrameStreamSockOutput's address, establishing
// the connection as needed.
//
// RunOutputLoop satisifes the dnstap Output interface.
func (o *FrameStreamSockOutput) RunOutputLoop() {
	var tenc timedEnc
	var conn net.Conn
	var err error

	go tenc.RunTimeoutLoop(o.flushTimeout)

	for frame := range o.outputChannel {
		tenc.mutex.Lock()

		for ;; time.Sleep(o.retry) {
			// need to connect to the remote endpoint?
			if tenc.enc == nil {
				conn, err = o.dialer.Dial(o.address.Network(), o.address.String())
				if err != nil {
					log.Printf("Dial() failed: %v", err)
					continue
				}

				tenc.enc, err = framestream.NewEncoder(conn, &framestream.EncoderOptions{
					ContentType:   FSContentType,
					Bidirectional: true,
					Timeout:       o.timeout,
				})
				if err != nil {
					log.Printf("framestream.NewEncoder() failed: %v", err)
					conn.Close()
					tenc.enc = nil
					continue
				}
			}

			// try writing
			if _, err = tenc.enc.Write(frame); err != nil {
				log.Printf("framestream.Encoder.Write() failed: %v", err)
				tenc.enc.Close()
				tenc.enc = nil
				conn.Close()
				continue
			}

			// success
			tenc.lastwrite = nanotime()
			break
		}

		tenc.mutex.Unlock()
	}

	// cleanup
	tenc.Stop()
	if conn != nil {
		conn.Close()
	}
	close(o.wait)
}

// Close shuts down the FrameStreamSockOutput's output channel and returns
// after all pending data has been flushed and the connection has been closed.
//
// Close satisifes the dnstap Output interface
func (o *FrameStreamSockOutput) Close() {
	close(o.outputChannel)
	<-o.wait
}
