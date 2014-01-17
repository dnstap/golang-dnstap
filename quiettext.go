package dnstap

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

import "bytes"
import "fmt"
import "net"
import "strconv"
import "time"

import "github.com/miekg/dns"

const quietTimeFormat = "15:04:05"

func textConvertTime(s *bytes.Buffer, secs *uint64, nsecs *uint32) {
    if secs != nil {
        s.WriteString(time.Unix(int64(*secs), 0).Format(quietTimeFormat))
    } else {
        s.WriteString("??:??:??")
    }
    if nsecs != nil {
        s.WriteString(fmt.Sprintf(".%06d", *nsecs / 1000))
    } else {
        s.WriteString(".??????")
    }
}

func textConvertIP(s *bytes.Buffer, ip []byte) {
    if ip != nil {
        s.WriteString(net.IP(ip).String())
    } else {
        s.WriteString("MISSING_ADDRESS")
    }
}

func textConvertMessage(m *Message, s *bytes.Buffer) {
    isQuery := false
    printQueryAddress := false

    switch *m.Type {
    case Message_CLIENT_QUERY,
         Message_RESOLVER_QUERY,
         Message_AUTH_QUERY,
         Message_FORWARDER_QUERY:
            isQuery = true
    case Message_CLIENT_RESPONSE,
         Message_RESOLVER_RESPONSE,
         Message_AUTH_RESPONSE,
         Message_FORWARDER_RESPONSE:
            isQuery = false
    }

    if isQuery {
        textConvertTime(s, m.QueryTimeSec, m.QueryTimeNsec)
    } else {
        textConvertTime(s, m.ResponseTimeSec, m.ResponseTimeNsec)
    }
    s.WriteString(" ")

    switch *m.Type {
    case Message_CLIENT_QUERY,
         Message_CLIENT_RESPONSE: {
            s.WriteString("C")
         }
    case Message_RESOLVER_QUERY,
         Message_RESOLVER_RESPONSE: {
             s.WriteString("R")
         }
    case Message_AUTH_QUERY,
         Message_AUTH_RESPONSE: {
             s.WriteString("A")
         }
    case Message_FORWARDER_QUERY,
         Message_FORWARDER_RESPONSE: {
             s.WriteString("F")
         }
    case Message_STUB_QUERY,
         Message_STUB_RESPONSE: {
             s.WriteString("S")
         }
    }

    if isQuery {
        s.WriteString("Q ")
    } else {
        s.WriteString("R ")
    }

    switch *m.Type {
    case Message_CLIENT_QUERY,
         Message_CLIENT_RESPONSE,
         Message_AUTH_QUERY,
         Message_AUTH_RESPONSE:
            printQueryAddress = true
    }

    if printQueryAddress {
        textConvertIP(s, m.QueryAddress)
    } else {
        textConvertIP(s, m.ResponseAddress)
    }
    s.WriteString(" ")

    if m.SocketProtocol != nil {
        s.WriteString(m.SocketProtocol.String())
    }
    s.WriteString(" ")

    var err error
    msg := new(dns.Msg)
    if isQuery {
        s.WriteString(strconv.Itoa(len(m.QueryMessage)))
        s.WriteString("b ")
        err = msg.Unpack(m.QueryMessage)
    } else {
        s.WriteString(strconv.Itoa(len(m.ResponseMessage)))
        s.WriteString("b ")
        err = msg.Unpack(m.ResponseMessage)
    }

    if err != nil {
        s.WriteString("X ")
    } else {
        s.WriteString(msg.Question[0].Name + " ")
        s.WriteString(dns.Class(msg.Question[0].Qclass).String() + " ")
        s.WriteString(dns.Type(msg.Question[0].Qtype).String())
    }

    s.WriteString("\n")
}

func textConvertPayload(dt *Dnstap) (out []byte) {
    var s bytes.Buffer

    if *dt.Type == Dnstap_MESSAGE {
        textConvertMessage(dt.Message, &s)
    }

    return s.Bytes()
}

func QuietTextConvert(buf []byte) (out []byte, ok bool) {
    dt, ok := Unpack(buf)
    if ok {
        return textConvertPayload(dt), true
    }
    return nil, false
}
