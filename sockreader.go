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
import "net"
import "os"

type SockReader struct {
    Convert     func([]byte) ([]byte, bool)
    listen      net.Listener
}

func NewSockReader(listen net.Listener) (s *SockReader) {
    s = new(SockReader)
    s.listen = listen
    return s
}

func NewSockReaderFromPath(socketPath string) (s *SockReader, err error) {
    os.Remove(socketPath)
    listen, err := net.Listen("unix", socketPath)
    if err != nil {
        return nil, err
    }
    return NewSockReader(listen), nil
}

func (s *SockReader) ReadInto(output chan []byte) {
    for {
        conn, err := s.listen.Accept()
        if err != nil {
            log.Printf("listen.Accept() failed: %s\n", err)
            continue
        }
        r, err := NewReader(conn)
        if err != nil {
            log.Printf("NewReader() failed: %s\n", err)
            continue
        }
        log.Printf("accepted a socket connection\n")
        r.Convert = s.Convert
        go r.ReadInto(output)
    }
}
