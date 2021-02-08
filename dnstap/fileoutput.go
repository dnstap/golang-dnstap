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

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	dnstap "github.com/dnstap/golang-dnstap"
)

// Output channel buffer size value from main dnstap package.
const outputChannelSize = 32

//
// A fileOutput implements a dnstap.Output which writes frames to a file
// and closes and reopens the file on SIGHUP.
//
// Data frames are written in binary fstrm format unless a text formatting
// function (dnstp.TextFormatFunc) is given or the filename is blank or "-".
// In the latter case, data is written in compact (quiet) text format unless
// an alternate text format is given on the assumption that stdout is a terminal.
//
type fileOutput struct {
	formatter dnstap.TextFormatFunc
	filename  string
	doAppend  bool
	output    dnstap.Output
	data      chan []byte
	done      chan struct{}
}

func openOutputFile(filename string, formatter dnstap.TextFormatFunc, doAppend bool) (o dnstap.Output, err error) {
	var fso *dnstap.FrameStreamOutput
	var to *dnstap.TextOutput
	if formatter == nil {
		if filename == "-" || filename == "" {
			to = dnstap.NewTextOutput(os.Stdout, dnstap.TextFormat)
			to.SetLogger(logger)
			return to, nil
		}
		fso, err = dnstap.NewFrameStreamOutputFromFilename(filename)
		if err == nil {
			fso.SetLogger(logger)
			return fso, nil
		}
	} else {
		if filename == "-" || filename == "" {
			if doAppend {
				return nil, errors.New("cannot append to stdout (-)")
			}
			to = dnstap.NewTextOutput(os.Stdout, formatter)
			to.SetLogger(logger)
			return to, nil
		}
		to, err = dnstap.NewTextOutputFromFilename(filename, formatter, doAppend)
		if err == nil {
			to.SetLogger(logger)
		}
		return to, nil
	}
	return
}

func newFileOutput(filename string, formatter dnstap.TextFormatFunc, doAppend bool) (*fileOutput, error) {
	o, err := openOutputFile(filename, formatter, doAppend)
	if err != nil {
		return nil, err
	}
	return &fileOutput{
		formatter: formatter,
		filename:  filename,
		doAppend:  doAppend,
		output:    o,
		data:      make(chan []byte, outputChannelSize),
		done:      make(chan struct{}),
	}, nil
}

func (fo *fileOutput) GetOutputChannel() chan []byte {
	return fo.data
}

func (fo *fileOutput) Close() {
	close(fo.data)
	<-fo.done
}

func (fo *fileOutput) RunOutputLoop() {
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, syscall.SIGHUP)
	o := fo.output
	go o.RunOutputLoop()
	defer func() {
		o.Close()
		close(fo.done)
	}()
	for {
		select {
		case b, ok := <-fo.data:
			if !ok {
				return
			}
			o.GetOutputChannel() <- b
		case sig := <-sigch:
			if sig == syscall.SIGHUP {
				o.Close()
				newo, err := openOutputFile(fo.filename, fo.formatter, fo.doAppend)
				if err != nil {
					fmt.Fprintf(os.Stderr,
						"dnstap: Error: failed to reopen %s: %v\n",
						fo.filename, err)
					os.Exit(1)
				}
				o = newo
				go o.RunOutputLoop()
				continue
			}
			os.Exit(0)
		}
	}
}
