package dnstap

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func dialAndSend(t *testing.T, network, address string) *FrameStreamSockOutput {
	var addr net.Addr
	var err error
	switch network {
	case "unix":
		addr, err = net.ResolveUnixAddr(network, address)
	case "tcp", "tcp4", "tcp6":
		addr, err = net.ResolveTCPAddr(network, address)
	default:
		err = fmt.Errorf("invalid network %s", network)
	}
	if err != nil {
		t.Fatal(err)
	}

	var out *FrameStreamSockOutput
	outputChan := make(chan *FrameStreamSockOutput)

	go func() {
		o, err := NewFrameStreamSockOutput(addr)
		if err != nil {
			t.Fatal(err)
		}

		o.SetDialer(&net.Dialer{Timeout: time.Second})
		o.SetTimeout(time.Second)
		o.SetRetryInterval(time.Second)

		outputChan <- o
	}()

	select {
	case out = <-outputChan:
	case <-time.After(time.Second):
		t.Fatal("can't create a new encoder")
	}

	go out.RunOutputLoop()
	out.GetOutputChannel() <- []byte("frame")
	return out
}

func readOne(t *testing.T, out chan []byte) {
	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for frame")
	}
}

// Test if dnstap can accept multiple connections on the socket
func TestMultiConn(t *testing.T) {
	in, err := NewFrameStreamSockInputFromPath("dnstap.sock")
	if err != nil {
		t.Fatal(err)
	}

	out := make(chan []byte)
	go in.ReadInto(out)

	// send two framestream messages on different connections
	defer dialAndSend(t, "unix", "dnstap.sock").Close()
	defer dialAndSend(t, "unix", "dnstap.sock").Close()

	readOne(t, out)
	readOne(t, out)
}

func TestReconnect(t *testing.T) {
	// Find an open port on localhost by opening a listener on an
	// unspecified port, querying its address, then closing it.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	laddr := l.Addr()
	l.Close()

	defer dialAndSend(t, laddr.Network(), laddr.String()).Close()
	defer dialAndSend(t, laddr.Network(), laddr.String()).Close()
	time.Sleep(1500 * time.Millisecond)
	l, err = net.Listen(laddr.Network(), laddr.String())
	if err != nil {
		t.Fatal(err)
	}

	in := NewFrameStreamSockInput(l)
	out := make(chan []byte)
	go in.ReadInto(out)
	readOne(t, out)
	readOne(t, out)
}
