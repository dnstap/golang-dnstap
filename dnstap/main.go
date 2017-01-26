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
import "log"
import "os"
import "os/signal"
import "runtime"
import "syscall"

import "golang-dnstap"

var (
    flagReadFile    = flag.String("r", "", "read dnstap payloads from file")
    flagReadSock    = flag.String("u", "", "read dnstap payloads from unix socket")
    flagWriteFile   = flag.String("w", "-", "write output to file")
    flagQuietText   = flag.Bool("q", false, "use quiet text output")
    flagYamlText    = flag.Bool("y", false, "use verbose YAML output")
)

func usage() {
    fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
    flag.PrintDefaults()
    fmt.Fprintf(os.Stderr, `
Quiet text output format mnemonics:
    AQ: AUTH_QUERY
    AR: AUTH_RESPONSE
    RQ: RESOLVER_QUERY
    RR: RESOLVER_RESPONSE
    CQ: CLIENT_QUERY
    CR: CLIENT_RESPONSE
    FQ: FORWARDER_QUERY
    FR: FORWARDER_RESPONSE
    SQ: STUB_QUERY
    SR: STUB_RESPONSE
    TQ: TOOL_QUERY
    TR: TOOL_RESPONSE
`)
}

func main() {
    var err error
    var i dnstap.Input
    var o dnstap.Output

    runtime.GOMAXPROCS(runtime.NumCPU())
    log.SetFlags(0)
    flag.Usage = usage

    // Handle command-line arguments.
    flag.Parse()

    if *flagReadFile == "" && *flagReadSock == "" {
        fmt.Fprintf(os.Stderr, "dnstap: Error: no inputs specified.\n")
        os.Exit(1)
    }

    if *flagWriteFile == "-" {
        if *flagQuietText == false && *flagYamlText == false {
            *flagQuietText = true
        }
    }

    if *flagReadFile != "" && *flagReadSock != "" {
        fmt.Fprintf(os.Stderr, "dnstap: Error: specify exactly one of -r or -u.\n")
        os.Exit(1)
    }

    // Open the output and start the output loop.
    if *flagQuietText {
        o, err = dnstap.NewTextOutputFromFilename(*flagWriteFile, dnstap.TextFormat)
    } else if *flagYamlText {
        o, err = dnstap.NewTextOutputFromFilename(*flagWriteFile, dnstap.YamlFormat)
    } else {
        o, err = dnstap.NewFrameStreamOutputFromFilename(*flagWriteFile)
    }
    if err != nil {
        fmt.Fprintf(os.Stderr, "dnstap: Failed to open output file: %s\n", err)
        os.Exit(1)
    }
    go o.RunOutputLoop()

    // Handle SIGINT and SIGHUP
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGHUP)
    go func(){
        for sig := range c {
            // Reopen the output file if HUP signal
            if sig == syscall.SIGHUP {
                o.Reopen()
            } else {
                o.Close()
                os.Exit(0)
            }
        }
    }()

    // Open the input and start the input loop.
    if *flagReadFile != "" {
        i, err = dnstap.NewFrameStreamInputFromFilename(*flagReadFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "dnstap: Failed to open input file: %s\n", err)
            os.Exit(1)
        }
        fmt.Fprintf(os.Stderr, "dnstap: opened input file %s\n", *flagReadFile)
    } else if *flagReadSock != "" {
        i, err = dnstap.NewFrameStreamSockInputFromPath(*flagReadSock)
        if err != nil {
            fmt.Fprintf(os.Stderr, "dnstap: Failed to open input socket: %s\n", err)
            os.Exit(1)
        }
        fmt.Fprintf(os.Stderr, "dnstap: opened input socket %s\n", *flagReadSock)
    }
    go i.ReadInto(o.GetOutputChannel())

    // Wait for input loop to finish.
    i.Wait()

    // Shut down the output loop.
    o.Close()
}
