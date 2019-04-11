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

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"github.com/dnstap/golang-dnstap"
)

var (
	flagReadTcp    = flag.String("l", "", "read dnstap payloads from tcp/ip")
	flagWriteTcp   = flag.String("T", "", "write dnstap payloads to tcp/ip address")
	flagTimeout    = flag.Duration("t", 0, "I/O timeout for tcp/ip and unix domain sockets")
	flagReadFile   = flag.String("r", "", "read dnstap payloads from file")
	flagReadSock   = flag.String("u", "", "read dnstap payloads from unix socket")
	flagWriteUnix  = flag.String("U", "", "write dnstap payloads to unix socket")
	flagWriteFile  = flag.String("w", "-", "write output to file")
	flagAppendFile = flag.Bool("a", false, "append to the given file, do not overwrite. valid only when outputting a text or YAML file.")
	flagQuietText  = flag.Bool("q", false, "use quiet text output")
	flagYamlText   = flag.Bool("y", false, "use verbose YAML output")
	flagJsonText   = flag.Bool("j", false, "use verbose JSON output")
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

	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetFlags(0)
	flag.Usage = usage

	// Handle command-line arguments.
	flag.Parse()

	haveInput := false
	for _, f := range []string{*flagReadFile, *flagReadSock, *flagReadTcp} {
		if haveInput && f != "" {
			fmt.Fprintf(os.Stderr, "dnstap: Error: specify exactly one of -r, -u or -l.\n")
			os.Exit(1)
		}
		haveInput = haveInput || f != ""
	}
	if !haveInput {
		fmt.Fprintf(os.Stderr, "dnstap: Error: no inputs specified.\n")
		os.Exit(1)
	}

	haveFormat := false
	for _, f := range []bool{*flagQuietText, *flagYamlText, *flagJsonText} {
		if haveFormat && f {
			fmt.Fprintf(os.Stderr, "dnstap: Error: specify at most one of -q, -y, or -j.\n")
			os.Exit(1)
		}
		haveFormat = haveFormat || f
	}

	if *flagWriteFile == "-" || *flagWriteFile == "" {
		if !haveFormat {
			*flagQuietText = true
		}
	}

	if *flagAppendFile == true {
		if *flagWriteFile == "-" || *flagWriteFile == "" {
			fmt.Fprintf(os.Stderr, "dnstap: Error: -a must specify the file output path.\n")
			os.Exit(1)
		}
	}

	var output dnstap.Output

	// Start the output loop.
	if *flagWriteTcp == "" && *flagWriteUnix == "" {
		var format dnstap.TextFormatFunc
		switch {
		case *flagJsonText:
			format = dnstap.JsonFormat
		case *flagQuietText:
			format = dnstap.TextFormat
		case *flagYamlText:
			format = dnstap.YamlFormat
		}
		output, err = newFileOutput(*flagWriteFile, format, *flagAppendFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Error writing to file %s: %v",
				*flagWriteFile, err)
		}
		go output.RunOutputLoop()
	} else {
		var addr net.Addr
		if *flagWriteTcp != "" {
			addr, err = net.ResolveTCPAddr("tcp", *flagWriteTcp)
		} else {
			addr, err = net.ResolveUnixAddr("unix", *flagWriteUnix)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Error: invalid address: %v", err)
			os.Exit(1)
		}
		so, err := dnstap.NewFrameStreamSockOutput(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Error: failed to open socket output: %v", err)
			os.Exit(1)
		}
		so.SetTimeout(*flagTimeout)
		go so.RunOutputLoop()
		output = so
	}

	// Open the input and start the input loop.
	if *flagReadFile != "" {
		i, err = dnstap.NewFrameStreamInputFromFilename(*flagReadFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input file: %s\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "dnstap: opened input file %s\n", *flagReadFile)
	} else if *flagReadSock != "" {
		var si *dnstap.FrameStreamSockInput
		si, err = dnstap.NewFrameStreamSockInputFromPath(*flagReadSock)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input socket: %s\n", err)
			os.Exit(1)
		}
		si.SetTimeout(*flagTimeout)
		i = si
		fmt.Fprintf(os.Stderr, "dnstap: opened input socket %s\n", *flagReadSock)
	} else if *flagReadTcp != "" {
		l, err := net.Listen("tcp", *flagReadTcp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to listen: %s\n", err)
			os.Exit(1)
		}
		si := dnstap.NewFrameStreamSockInput(l)
		si.SetTimeout(*flagTimeout)
		i = si
	}
	go i.ReadInto(output.GetOutputChannel())
	i.Wait()

	output.Close()
}
