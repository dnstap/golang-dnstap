package dnstap

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

type testLogger struct{ *testing.T }

func (t *testLogger) Printf(format string, v ...interface{}) {
	t.Helper()
	t.Logf(format, v...)
}

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

	out, err := NewFrameStreamSockOutput(addr)
	if err != nil {
		t.Fatal(err)
	}

	out.SetDialer(&net.Dialer{Timeout: time.Second})
	out.SetTimeout(time.Second)
	out.SetFlushTimeout(100 * time.Millisecond)
	out.SetRetryInterval(time.Second)
	out.SetLogger(&testLogger{t})

	go out.RunOutputLoop()
	<-time.After(500 * time.Millisecond)
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

	defer os.Remove("dnstap.sock")

	in.SetLogger(&testLogger{t})
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
	in.SetLogger(&testLogger{t})
	out := make(chan []byte)
	go in.ReadInto(out)
	readOne(t, out)
	readOne(t, out)
}

func BenchmarkConnectUnidirectional(b *testing.B) {
	b.StopTimer()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatal(err)
	}

	// read from tcp socket into outch
	outch := make(chan []byte, 32)
	go func() {
		// wait for connection
		s, err := l.Accept()
		if err != nil {
			b.Error(err)
			close(outch)
			return
		}

		// start rewriter
		in, err := NewFrameStreamInput(s, false)
		if err != nil {
			b.Error(err)
			close(outch)
			return
		}

		// read ASAP into outch
		in.ReadInto(outch)
		close(outch)
	}()

	// read from outch exactly b.N frames
	// this is separate from the above, because the process of rewriting tcp into outch
	// must run in parallel with reading b.N frames from outch
	readDone := make(chan struct{})
	go func() {
		// wait for the first frame before starting the timer
		<-outch
		i := 1

		b.StartTimer()
		for _ = range outch {
			i++
		}
		if i != b.N {
			b.Error("invalid frame count")
		}
		close(readDone)
	}()

	// connect to tcp socket and start the output loop
	c, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	out, err := NewFrameStreamOutput(c)
	if err != nil {
		b.Fatal(err)
	}
	go out.RunOutputLoop()

	// write to the output channel exactly b.N frames
	for i := 0; i < b.N; i++ {
		out.GetOutputChannel() <- []byte("frame")
	}
	out.Close()

	// wait for the reader
	<-readDone
}

func BenchmarkConnectBidirectional(b *testing.B) {
	b.StopTimer()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatal(err)
	}

	// start an infinite tcp socket reader
	in := NewFrameStreamSockInput(l)
	outch := make(chan []byte, 32)
	go in.ReadInto(outch)

	// read up to b.N frames in background
	readDone := make(chan struct{})
	go func() {
		<-outch
		b.StartTimer()
		for i := 1; i < b.N; i++ {
			<-outch
		} // NB: read never fails
		close(readDone)
	}()

	// connect to tcp socket and start the output loop
	out, err := NewFrameStreamSockOutput(l.Addr())
	if err != nil {
		b.Fatal(err)
	}
	go out.RunOutputLoop()

	// write to the output channel exactly b.N frames
	for i := 0; i < b.N; i++ {
		out.GetOutputChannel() <- []byte("frame")
	}
	out.Close()

	// wait for the reader
	<-readDone
}
