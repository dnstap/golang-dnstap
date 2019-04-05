package dnstap

import (
	"net"
	"testing"
	"time"

	fs "github.com/farsightsec/golang-framestream"
)

func dialAndSend(t *testing.T) net.Conn {
	c, err := net.DialTimeout("unix", "dnstap.sock", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	var enc *fs.Encoder
	encChan := make(chan *fs.Encoder)

	go func() {
		enc, err := fs.NewEncoder(c, &fs.EncoderOptions{FSContentType, true})
		if err != nil {
			t.Fatal(err)
		}

		encChan <- enc
	}()

	select {
	case enc = <-encChan:
	case <-time.After(time.Second):
		t.Fatal("can't create a new encoder")
	}

	_, err = enc.Write([]byte("frame"))
	if err != nil {
		t.Fatal(err)
	}

	err = enc.Flush()
	if err != nil {
		t.Fatal(err)
	}

	return c
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
	defer dialAndSend(t).Close()
	defer dialAndSend(t).Close()

	readOne(t, out)
	readOne(t, out)
}
