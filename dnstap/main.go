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

package main

import "flag"
import "fmt"
import "os"
import "os/signal"
import "runtime"

import dnstap "github.com/dnstap/golang-dnstap"

const (
    channelSize     = 32
)

var (
    flagReadFile    = flag.String("r", "", "read dnstap payloads from file")
    flagReadSock    = flag.String("u", "", "read dnstap payloads from unix socket")
    flagWriteFile   = flag.String("w", "", "write output to file")
    flagQuietText   = flag.Bool("q", false, "use quiet text output")
    flagYamlText    = flag.Bool("y", false, "use verbose YAML output")
)

func main() {
    var err error
    var s *dnstap.SockReader
    var r *dnstap.Reader
    var w *dnstap.Writer
    var convert func([]byte) ([]byte, bool)
    var unbuffered bool

    runtime.GOMAXPROCS(runtime.NumCPU())

    flag.Parse()
    if *flagQuietText || (*flagWriteFile == "" || *flagWriteFile == "-") {
        convert = dnstap.QuietTextConvert
    }
    if *flagYamlText {
        convert = dnstap.YamlConvert
    }
    if *flagWriteFile == "" || *flagWriteFile == "-" {
        unbuffered = true
    }
    if *flagReadFile == "" && *flagReadSock == "" {
        fmt.Fprintf(os.Stderr, "dnstap: Error: no inputs, specify -r or -u\n")
        os.Exit(1)
    }
    if *flagReadFile != "" && *flagReadSock != "" {
        fmt.Fprintf(os.Stderr, "dnstap: Error: specify exactly one of -r or -u\n")
        os.Exit(1)
    }

    /* writer */
    w, err = dnstap.NewWriterFromFilename(*flagWriteFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "dnstap: failed to open output file: %s\n", err)
        os.Exit(1)
    }
    w.Unbuffered = unbuffered

    /* reader */
    if *flagReadFile != "" {
        r, err = dnstap.NewReaderFromFilename(*flagReadFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "dnstap: failed to open input file: %s\n", err)
            os.Exit(1)
        }
        r.Convert = convert
    } else if *flagReadSock != "" {
        s, err = dnstap.NewSockReaderFromPath(*flagReadSock)
        if err != nil {
            fmt.Fprintf(os.Stderr, "dnstap: failed to open input socket: %s\n", err)
            os.Exit(1)
        }
        s.Convert = convert
        fmt.Fprintf(os.Stderr, "dnstap: opened input socket: %s\n", *flagReadSock)
    }

    outputChannel := make(chan []byte, channelSize)

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    go func(){
        for _ = range c {
            close(outputChannel)
            w.Wait()
            os.Exit(0)
        }
    }()
    go w.Write(outputChannel)

    if r != nil {
        go r.ReadInto(outputChannel)
        r.Wait()
        close(outputChannel)
        w.Wait()
    } else if s != nil {
        s.ReadInto(outputChannel)
    }
}
