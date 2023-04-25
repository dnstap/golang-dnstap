/*
 * Copyright (c) 2013-2019 by Farsight Security, Inc.
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
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// A FrameStreamSockInput collects dnstap data from one or more clients of
// a listening socket.
type FrameStreamSockInput struct {
	wait     chan struct{}
	listener net.Listener
	timeout  time.Duration
	log      Logger
}

// NewFrameStreamSockInput creates a FrameStreamSockInput collecting dnstap
// data from clients which connect to the given listener.
func NewFrameStreamSockInput(listener net.Listener) (input *FrameStreamSockInput) {
	input = &FrameStreamSockInput{
		wait:     make(chan struct{}),
		listener: listener,
		log:      &nullLogger{},
	}
	return
}

// SetTimeout sets the timeout for reading the initial handshake and writing
// response control messages to clients of the FrameStreamSockInput's listener.
//
// The timeout is effective only for connections accepted after the call to
// SetTimeout.
func (input *FrameStreamSockInput) SetTimeout(timeout time.Duration) {
	input.timeout = timeout
}

// SetLogger configures a logger for the FrameStreamSockInput.
func (input *FrameStreamSockInput) SetLogger(logger Logger) {
	input.log = logger
}

// NewFrameStreamSockInputFromPath creates a unix domain socket at the
// given socketPath and returns a FrameStreamSockInput collecting dnstap
// data from clients connecting to this socket.
//
// If a socket or other file already exists at socketPath,
// NewFrameStreamSockInputFromPath removes it before creating the socket.
func NewFrameStreamSockInputFromPath(socketPath string) (input *FrameStreamSockInput, err error) {
	os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return
	}
	return NewFrameStreamSockInput(listener), nil
}

// ReadInto accepts connections to the FrameStreamSockInput's listening
// socket and sends all dnstap data read from these connections to the
// output channel. It blocks until `Close` is called.
//
// ReadInto satisfies the dnstap Input interface.
func (input *FrameStreamSockInput) ReadInto(output chan []byte) {
	var (
		n     = uint64(0)                 // connection counter
		m     sync.Mutex                  // protects conns
		conns = make(map[uint64]net.Conn) // map of active connections
		wg    = &sync.WaitGroup{}         // wait group for the termination
	)

	for {
		conn, err := input.listener.Accept()
		if err != nil {
			input.log.Printf("%s: accept failed: %v\n", input.listener.Addr(), err)

			if errors.Is(err, net.ErrClosed) {
				// net.ErrClosed is returned when the listener has been closed
				break
			}

			continue
		}

		n++
		origin := ""

		switch conn.RemoteAddr().Network() {
		case "tcp", "tcp4", "tcp6":
			origin = fmt.Sprintf(" from %s", conn.RemoteAddr())
		}

		i, err := NewFrameStreamInputTimeout(conn, true, input.timeout)
		if err != nil {
			input.log.Printf("%s: connection %d: open input%s failed: %v", conn.LocalAddr(), n, origin, err)
			continue
		}

		input.log.Printf("%s: accepted connection %d%s", conn.LocalAddr(), n, origin)
		i.SetLogger(input.log)

		// store the connection so we can close it later
		m.Lock()
		conns[n] = conn
		m.Unlock()

		wg.Add(1)
		go func(cn uint64) {
			defer wg.Done()

			// read from the connection into the output
			i.ReadInto(output)
			input.log.Printf("%s: closed connection %d%s", conn.LocalAddr(), cn, origin)

			// delete our connection from the map
			m.Lock()
			delete(conns, n)
			m.Unlock()
		}(n)
	}

	// close all active connections
	m.Lock()
	input.log.Printf("listener has been closed, closing all %d active connections", len(conns))

	for _, c := range conns {
		c.Close()
	}
	m.Unlock()

	// wait for the readers to terminate
	wg.Wait()
	close(input.wait)
}

// Wait for the `ReadInto` method to terminate. It will block forever if you never call `ReadInto`.
// After Wait has returned, all connections and the listener have been closed.
// Wait satisfies the dnstap Input interface.
func (input *FrameStreamSockInput) Wait() {
	<-input.wait
}

// Close terminates the processing of incoming connections by closing the listener. It does not
// wait for the connection handlers or `ReadInto` to stop, you can use the `Wait` method for that.
// The output channel will not be closed automatically. `ReadInto` will return after this method
// has been called and all workers have stopped. Don't reuse a closed instance of
// FrameStreamSockInput.
func (input *FrameStreamSockInput) Close() error {
	return input.listener.Close()
}
