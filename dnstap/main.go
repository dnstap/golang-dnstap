package main

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
    flagReadSock    = flag.String("s", "", "read dnstap payloads from unix socket")
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
        fmt.Fprintf(os.Stderr, "dnstap: Error: no inputs, specify -r or -s\n")
        os.Exit(1)
    }
    if *flagReadFile != "" && *flagReadSock != "" {
        fmt.Fprintf(os.Stderr, "dnstap: Error: specify exactly one of -r or -n\n")
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
        go r.Read(outputChannel)
        r.Wait()
        close(outputChannel)
        w.Wait()
    } else if s != nil {
        s.Read(outputChannel)
    }
}
