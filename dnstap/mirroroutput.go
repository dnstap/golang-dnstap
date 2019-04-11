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
	dnstap "github.com/dnstap/golang-dnstap"
)

type mirrorOutput struct {
	outputs []dnstap.Output
	data    chan []byte
	done    chan struct{}
}

func newMirrorOutput() *mirrorOutput {
	return &mirrorOutput{
		data: make(chan []byte, outputChannelSize),
		done: make(chan struct{}),
	}
}

func (mo *mirrorOutput) Add(o dnstap.Output) {
	mo.outputs = append(mo.outputs, o)
}

func (mo *mirrorOutput) RunOutputLoop() {
	for b := range mo.data {
		for _, o := range mo.outputs {
			select {
			case o.GetOutputChannel() <- b:
			default:
			}
		}
	}
	for _, o := range mo.outputs {
		o.Close()
	}
	close(mo.done)
}

func (mo *mirrorOutput) Close() {
	close(mo.data)
	<-mo.done
}

func (mo *mirrorOutput) GetOutputChannel() chan []byte {
	return mo.data
}
