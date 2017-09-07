// Code generated by protoc-gen-go. DO NOT EDIT.
// source: dnstap.proto

/*
Package dnstap is a generated protocol buffer package.

It is generated from these files:
	dnstap.proto

It has these top-level messages:
	Dnstap
	Message
*/
package dnstap

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// SocketFamily: the network protocol family of a socket. This specifies how
// to interpret "network address" fields.
type SocketFamily int32

const (
	SocketFamily_INET  SocketFamily = 1
	SocketFamily_INET6 SocketFamily = 2
)

var SocketFamily_name = map[int32]string{
	1: "INET",
	2: "INET6",
}
var SocketFamily_value = map[string]int32{
	"INET":  1,
	"INET6": 2,
}

func (x SocketFamily) Enum() *SocketFamily {
	p := new(SocketFamily)
	*p = x
	return p
}
func (x SocketFamily) String() string {
	return proto.EnumName(SocketFamily_name, int32(x))
}
func (x *SocketFamily) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(SocketFamily_value, data, "SocketFamily")
	if err != nil {
		return err
	}
	*x = SocketFamily(value)
	return nil
}
func (SocketFamily) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// SocketProtocol: the transport protocol of a socket. This specifies how to
// interpret "transport port" fields.
type SocketProtocol int32

const (
	SocketProtocol_UDP SocketProtocol = 1
	SocketProtocol_TCP SocketProtocol = 2
)

var SocketProtocol_name = map[int32]string{
	1: "UDP",
	2: "TCP",
}
var SocketProtocol_value = map[string]int32{
	"UDP": 1,
	"TCP": 2,
}

func (x SocketProtocol) Enum() *SocketProtocol {
	p := new(SocketProtocol)
	*p = x
	return p
}
func (x SocketProtocol) String() string {
	return proto.EnumName(SocketProtocol_name, int32(x))
}
func (x *SocketProtocol) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(SocketProtocol_value, data, "SocketProtocol")
	if err != nil {
		return err
	}
	*x = SocketProtocol(value)
	return nil
}
func (SocketProtocol) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

// Identifies which field below is filled in.
type Dnstap_Type int32

const (
	Dnstap_MESSAGE Dnstap_Type = 1
)

var Dnstap_Type_name = map[int32]string{
	1: "MESSAGE",
}
var Dnstap_Type_value = map[string]int32{
	"MESSAGE": 1,
}

func (x Dnstap_Type) Enum() *Dnstap_Type {
	p := new(Dnstap_Type)
	*p = x
	return p
}
func (x Dnstap_Type) String() string {
	return proto.EnumName(Dnstap_Type_name, int32(x))
}
func (x *Dnstap_Type) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(Dnstap_Type_value, data, "Dnstap_Type")
	if err != nil {
		return err
	}
	*x = Dnstap_Type(value)
	return nil
}
func (Dnstap_Type) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

type Message_Type int32

const (
	// AUTH_QUERY is a DNS query message received from a resolver by an
	// authoritative name server, from the perspective of the authorative
	// name server.
	Message_AUTH_QUERY Message_Type = 1
	// AUTH_RESPONSE is a DNS response message sent from an authoritative
	// name server to a resolver, from the perspective of the authoritative
	// name server.
	Message_AUTH_RESPONSE Message_Type = 2
	// RESOLVER_QUERY is a DNS query message sent from a resolver to an
	// authoritative name server, from the perspective of the resolver.
	// Resolvers typically clear the RD (recursion desired) bit when
	// sending queries.
	Message_RESOLVER_QUERY Message_Type = 3
	// RESOLVER_RESPONSE is a DNS response message received from an
	// authoritative name server by a resolver, from the perspective of
	// the resolver.
	Message_RESOLVER_RESPONSE Message_Type = 4
	// CLIENT_QUERY is a DNS query message sent from a client to a DNS
	// server which is expected to perform further recursion, from the
	// perspective of the DNS server. The client may be a stub resolver or
	// forwarder or some other type of software which typically sets the RD
	// (recursion desired) bit when querying the DNS server. The DNS server
	// may be a simple forwarding proxy or it may be a full recursive
	// resolver.
	Message_CLIENT_QUERY Message_Type = 5
	// CLIENT_RESPONSE is a DNS response message sent from a DNS server to
	// a client, from the perspective of the DNS server. The DNS server
	// typically sets the RA (recursion available) bit when responding.
	Message_CLIENT_RESPONSE Message_Type = 6
	// FORWARDER_QUERY is a DNS query message sent from a downstream DNS
	// server to an upstream DNS server which is expected to perform
	// further recursion, from the perspective of the downstream DNS
	// server.
	Message_FORWARDER_QUERY Message_Type = 7
	// FORWARDER_RESPONSE is a DNS response message sent from an upstream
	// DNS server performing recursion to a downstream DNS server, from the
	// perspective of the downstream DNS server.
	Message_FORWARDER_RESPONSE Message_Type = 8
	// STUB_QUERY is a DNS query message sent from a stub resolver to a DNS
	// server, from the perspective of the stub resolver.
	Message_STUB_QUERY Message_Type = 9
	// STUB_RESPONSE is a DNS response message sent from a DNS server to a
	// stub resolver, from the perspective of the stub resolver.
	Message_STUB_RESPONSE Message_Type = 10
	// TOOL_QUERY is a DNS query message sent from a DNS software tool to a
	// DNS server, from the perspective of the tool.
	Message_TOOL_QUERY Message_Type = 11
	// TOOL_RESPONSE is a DNS response message received by a DNS software
	// tool from a DNS server, from the perspective of the tool.
	Message_TOOL_RESPONSE Message_Type = 12
)

var Message_Type_name = map[int32]string{
	1:  "AUTH_QUERY",
	2:  "AUTH_RESPONSE",
	3:  "RESOLVER_QUERY",
	4:  "RESOLVER_RESPONSE",
	5:  "CLIENT_QUERY",
	6:  "CLIENT_RESPONSE",
	7:  "FORWARDER_QUERY",
	8:  "FORWARDER_RESPONSE",
	9:  "STUB_QUERY",
	10: "STUB_RESPONSE",
	11: "TOOL_QUERY",
	12: "TOOL_RESPONSE",
}
var Message_Type_value = map[string]int32{
	"AUTH_QUERY":         1,
	"AUTH_RESPONSE":      2,
	"RESOLVER_QUERY":     3,
	"RESOLVER_RESPONSE":  4,
	"CLIENT_QUERY":       5,
	"CLIENT_RESPONSE":    6,
	"FORWARDER_QUERY":    7,
	"FORWARDER_RESPONSE": 8,
	"STUB_QUERY":         9,
	"STUB_RESPONSE":      10,
	"TOOL_QUERY":         11,
	"TOOL_RESPONSE":      12,
}

func (x Message_Type) Enum() *Message_Type {
	p := new(Message_Type)
	*p = x
	return p
}
func (x Message_Type) String() string {
	return proto.EnumName(Message_Type_name, int32(x))
}
func (x *Message_Type) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(Message_Type_value, data, "Message_Type")
	if err != nil {
		return err
	}
	*x = Message_Type(value)
	return nil
}
func (Message_Type) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{1, 0} }

// "Dnstap": this is the top-level dnstap type, which is a "union" type that
// contains other kinds of dnstap payloads, although currently only one type
// of dnstap payload is defined.
// See: https://developers.google.com/protocol-buffers/docs/techniques#union
type Dnstap struct {
	// DNS server identity.
	// If enabled, this is the identity string of the DNS server which generated
	// this message. Typically this would be the same string as returned by an
	// "NSID" (RFC 5001) query.
	Identity []byte `protobuf:"bytes,1,opt,name=identity" json:"identity,omitempty"`
	// DNS server version.
	// If enabled, this is the version string of the DNS server which generated
	// this message. Typically this would be the same string as returned by a
	// "version.bind" query.
	Version []byte `protobuf:"bytes,2,opt,name=version" json:"version,omitempty"`
	// Extra data for this payload.
	// This field can be used for adding an arbitrary byte-string annotation to
	// the payload. No encoding or interpretation is applied or enforced.
	Extra []byte       `protobuf:"bytes,3,opt,name=extra" json:"extra,omitempty"`
	Type  *Dnstap_Type `protobuf:"varint,15,req,name=type,enum=dnstap.Dnstap_Type" json:"type,omitempty"`
	// One of the following will be filled in.
	Message                      *Message `protobuf:"bytes,14,opt,name=message" json:"message,omitempty"`
	proto.XXX_InternalExtensions `json:"-"`
	XXX_unrecognized             []byte `json:"-"`
}

func (m *Dnstap) Reset()                    { *m = Dnstap{} }
func (m *Dnstap) String() string            { return proto.CompactTextString(m) }
func (*Dnstap) ProtoMessage()               {}
func (*Dnstap) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

var extRange_Dnstap = []proto.ExtensionRange{
	{1000, 536870911},
}

func (*Dnstap) ExtensionRangeArray() []proto.ExtensionRange {
	return extRange_Dnstap
}

func (m *Dnstap) GetIdentity() []byte {
	if m != nil {
		return m.Identity
	}
	return nil
}

func (m *Dnstap) GetVersion() []byte {
	if m != nil {
		return m.Version
	}
	return nil
}

func (m *Dnstap) GetExtra() []byte {
	if m != nil {
		return m.Extra
	}
	return nil
}

func (m *Dnstap) GetType() Dnstap_Type {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return Dnstap_MESSAGE
}

func (m *Dnstap) GetMessage() *Message {
	if m != nil {
		return m.Message
	}
	return nil
}

// Message: a wire-format (RFC 1035 section 4) DNS message and associated
// metadata. Applications generating "Message" payloads should follow
// certain requirements based on the MessageType, see below.
type Message struct {
	// One of the Type values described above.
	Type *Message_Type `protobuf:"varint,1,req,name=type,enum=dnstap.Message_Type" json:"type,omitempty"`
	// One of the SocketFamily values described above.
	SocketFamily *SocketFamily `protobuf:"varint,2,opt,name=socket_family,json=socketFamily,enum=dnstap.SocketFamily" json:"socket_family,omitempty"`
	// One of the SocketProtocol values described above.
	SocketProtocol *SocketProtocol `protobuf:"varint,3,opt,name=socket_protocol,json=socketProtocol,enum=dnstap.SocketProtocol" json:"socket_protocol,omitempty"`
	// The network address of the message initiator.
	// For SocketFamily INET, this field is 4 octets (IPv4 address).
	// For SocketFamily INET6, this field is 16 octets (IPv6 address).
	QueryAddress []byte `protobuf:"bytes,4,opt,name=query_address,json=queryAddress" json:"query_address,omitempty"`
	// The network address of the message responder.
	// For SocketFamily INET, this field is 4 octets (IPv4 address).
	// For SocketFamily INET6, this field is 16 octets (IPv6 address).
	ResponseAddress []byte `protobuf:"bytes,5,opt,name=response_address,json=responseAddress" json:"response_address,omitempty"`
	// The transport port of the message initiator.
	// This is a 16-bit UDP or TCP port number, depending on SocketProtocol.
	QueryPort *uint32 `protobuf:"varint,6,opt,name=query_port,json=queryPort" json:"query_port,omitempty"`
	// The transport port of the message responder.
	// This is a 16-bit UDP or TCP port number, depending on SocketProtocol.
	ResponsePort *uint32 `protobuf:"varint,7,opt,name=response_port,json=responsePort" json:"response_port,omitempty"`
	// The time at which the DNS query message was sent or received, depending
	// on whether this is an AUTH_QUERY, RESOLVER_QUERY, or CLIENT_QUERY.
	// This is the number of seconds since the UNIX epoch.
	QueryTimeSec *uint64 `protobuf:"varint,8,opt,name=query_time_sec,json=queryTimeSec" json:"query_time_sec,omitempty"`
	// The time at which the DNS query message was sent or received.
	// This is the seconds fraction, expressed as a count of nanoseconds.
	QueryTimeNsec *uint32 `protobuf:"fixed32,9,opt,name=query_time_nsec,json=queryTimeNsec" json:"query_time_nsec,omitempty"`
	// The initiator's original wire-format DNS query message, verbatim.
	QueryMessage []byte `protobuf:"bytes,10,opt,name=query_message,json=queryMessage" json:"query_message,omitempty"`
	// The "zone" or "bailiwick" pertaining to the DNS query message.
	// This is a wire-format DNS domain name.
	QueryZone []byte `protobuf:"bytes,11,opt,name=query_zone,json=queryZone" json:"query_zone,omitempty"`
	// The time at which the DNS response message was sent or received,
	// depending on whether this is an AUTH_RESPONSE, RESOLVER_RESPONSE, or
	// CLIENT_RESPONSE.
	// This is the number of seconds since the UNIX epoch.
	ResponseTimeSec *uint64 `protobuf:"varint,12,opt,name=response_time_sec,json=responseTimeSec" json:"response_time_sec,omitempty"`
	// The time at which the DNS response message was sent or received.
	// This is the seconds fraction, expressed as a count of nanoseconds.
	ResponseTimeNsec *uint32 `protobuf:"fixed32,13,opt,name=response_time_nsec,json=responseTimeNsec" json:"response_time_nsec,omitempty"`
	// The responder's original wire-format DNS response message, verbatim.
	ResponseMessage  []byte `protobuf:"bytes,14,opt,name=response_message,json=responseMessage" json:"response_message,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *Message) Reset()                    { *m = Message{} }
func (m *Message) String() string            { return proto.CompactTextString(m) }
func (*Message) ProtoMessage()               {}
func (*Message) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Message) GetType() Message_Type {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return Message_AUTH_QUERY
}

func (m *Message) GetSocketFamily() SocketFamily {
	if m != nil && m.SocketFamily != nil {
		return *m.SocketFamily
	}
	return SocketFamily_INET
}

func (m *Message) GetSocketProtocol() SocketProtocol {
	if m != nil && m.SocketProtocol != nil {
		return *m.SocketProtocol
	}
	return SocketProtocol_UDP
}

func (m *Message) GetQueryAddress() []byte {
	if m != nil {
		return m.QueryAddress
	}
	return nil
}

func (m *Message) GetResponseAddress() []byte {
	if m != nil {
		return m.ResponseAddress
	}
	return nil
}

func (m *Message) GetQueryPort() uint32 {
	if m != nil && m.QueryPort != nil {
		return *m.QueryPort
	}
	return 0
}

func (m *Message) GetResponsePort() uint32 {
	if m != nil && m.ResponsePort != nil {
		return *m.ResponsePort
	}
	return 0
}

func (m *Message) GetQueryTimeSec() uint64 {
	if m != nil && m.QueryTimeSec != nil {
		return *m.QueryTimeSec
	}
	return 0
}

func (m *Message) GetQueryTimeNsec() uint32 {
	if m != nil && m.QueryTimeNsec != nil {
		return *m.QueryTimeNsec
	}
	return 0
}

func (m *Message) GetQueryMessage() []byte {
	if m != nil {
		return m.QueryMessage
	}
	return nil
}

func (m *Message) GetQueryZone() []byte {
	if m != nil {
		return m.QueryZone
	}
	return nil
}

func (m *Message) GetResponseTimeSec() uint64 {
	if m != nil && m.ResponseTimeSec != nil {
		return *m.ResponseTimeSec
	}
	return 0
}

func (m *Message) GetResponseTimeNsec() uint32 {
	if m != nil && m.ResponseTimeNsec != nil {
		return *m.ResponseTimeNsec
	}
	return 0
}

func (m *Message) GetResponseMessage() []byte {
	if m != nil {
		return m.ResponseMessage
	}
	return nil
}

func init() {
	proto.RegisterType((*Dnstap)(nil), "dnstap.Dnstap")
	proto.RegisterType((*Message)(nil), "dnstap.Message")
	proto.RegisterEnum("dnstap.SocketFamily", SocketFamily_name, SocketFamily_value)
	proto.RegisterEnum("dnstap.SocketProtocol", SocketProtocol_name, SocketProtocol_value)
	proto.RegisterEnum("dnstap.Dnstap_Type", Dnstap_Type_name, Dnstap_Type_value)
	proto.RegisterEnum("dnstap.Message_Type", Message_Type_name, Message_Type_value)
}

func init() { proto.RegisterFile("dnstap.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 589 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x92, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0x86, 0xb5, 0x69, 0x12, 0x27, 0x13, 0xc7, 0x71, 0xa7, 0xa5, 0xb2, 0x90, 0x90, 0xa2, 0x14,
	0x81, 0x1b, 0xa1, 0x1e, 0x7a, 0x40, 0xe2, 0x84, 0x42, 0xeb, 0x42, 0xa5, 0x34, 0x09, 0x6b, 0x07,
	0x04, 0x97, 0x28, 0x4a, 0x16, 0x64, 0xd1, 0xd8, 0xc6, 0x6b, 0x10, 0xe1, 0x94, 0xc7, 0x43, 0xe2,
	0x45, 0x38, 0xf1, 0x0c, 0xc8, 0xe3, 0xf5, 0xd6, 0xe1, 0xb6, 0xf3, 0xcf, 0x37, 0x33, 0xff, 0xce,
	0x2e, 0x98, 0xeb, 0x48, 0x66, 0xcb, 0xe4, 0x3c, 0x49, 0xe3, 0x2c, 0xc6, 0x66, 0x11, 0x0d, 0x7e,
	0x31, 0x68, 0x5e, 0xd1, 0x11, 0x1f, 0x42, 0x2b, 0x5c, 0x8b, 0x28, 0x0b, 0xb3, 0xad, 0xc3, 0xfa,
	0xcc, 0x35, 0xb9, 0x8e, 0xd1, 0x01, 0xe3, 0xbb, 0x48, 0x65, 0x18, 0x47, 0x4e, 0x8d, 0x52, 0x65,
	0x88, 0xc7, 0xd0, 0x10, 0x3f, 0xb2, 0x74, 0xe9, 0x1c, 0x90, 0x5e, 0x04, 0xf8, 0x14, 0xea, 0xd9,
	0x36, 0x11, 0x4e, 0xaf, 0x5f, 0x73, 0xad, 0x8b, 0xa3, 0x73, 0x35, 0xbb, 0x98, 0x74, 0x1e, 0x6c,
	0x13, 0xc1, 0x09, 0xc0, 0x33, 0x30, 0x36, 0x42, 0xca, 0xe5, 0x67, 0xe1, 0x58, 0x7d, 0xe6, 0x76,
	0x2e, 0x7a, 0x25, 0x7b, 0x5b, 0xc8, 0xbc, 0xcc, 0x0f, 0x8e, 0xa0, 0x9e, 0x17, 0x62, 0x07, 0x8c,
	0x5b, 0xcf, 0xf7, 0x47, 0xaf, 0x3d, 0x9b, 0x0d, 0xdb, 0xad, 0x3f, 0x86, 0xbd, 0xdb, 0xed, 0x76,
	0xb5, 0xc1, 0xef, 0x26, 0x18, 0xaa, 0x08, 0x5d, 0x35, 0x9f, 0xd1, 0xfc, 0xe3, 0xff, 0x7a, 0x56,
	0x0d, 0xbc, 0x80, 0xae, 0x8c, 0x57, 0x5f, 0x44, 0xb6, 0xf8, 0xb4, 0xdc, 0x84, 0x77, 0x5b, 0xba,
	0x5f, 0xa5, 0xc4, 0xa7, 0xe4, 0x35, 0xe5, 0xb8, 0x29, 0x2b, 0x11, 0xbe, 0x84, 0x9e, 0x2a, 0xa5,
	0x9d, 0xae, 0xe2, 0x3b, 0x5a, 0x82, 0x75, 0x71, 0xb2, 0x5f, 0x3c, 0x53, 0x59, 0x6e, 0xc9, 0xbd,
	0x18, 0x4f, 0xa1, 0xfb, 0xf5, 0x9b, 0x48, 0xb7, 0x8b, 0xe5, 0x7a, 0x9d, 0x0a, 0x29, 0x9d, 0x3a,
	0xed, 0xd0, 0x24, 0x71, 0x54, 0x68, 0x78, 0x06, 0x76, 0x2a, 0x64, 0x12, 0x47, 0x52, 0x68, 0xae,
	0x41, 0x5c, 0xaf, 0xd4, 0x4b, 0xf4, 0x11, 0x40, 0xd1, 0x2f, 0x89, 0xd3, 0xcc, 0x69, 0xf6, 0x99,
	0xdb, 0xe5, 0x6d, 0x52, 0x66, 0x71, 0x9a, 0xe5, 0xe3, 0x74, 0x27, 0x22, 0x0c, 0x22, 0xcc, 0x52,
	0x24, 0xe8, 0x31, 0x58, 0x45, 0x8f, 0x2c, 0xdc, 0x88, 0x85, 0x14, 0x2b, 0xa7, 0xd5, 0x67, 0x6e,
	0x5d, 0x99, 0x0a, 0xc2, 0x8d, 0xf0, 0xc5, 0x0a, 0x9f, 0x40, 0xaf, 0x42, 0x45, 0x39, 0xd6, 0xee,
	0x33, 0xd7, 0xe0, 0x5d, 0x8d, 0x4d, 0xa4, 0x58, 0xdd, 0xdf, 0xb0, 0x7c, 0x64, 0xa8, 0xdc, 0xb0,
	0x7c, 0x2c, 0x6d, 0xfb, 0x67, 0x1c, 0x09, 0xa7, 0x43, 0x44, 0x61, 0xfb, 0x63, 0x1c, 0x09, 0x1c,
	0xc2, 0xa1, 0xb6, 0xad, 0x4d, 0x99, 0x64, 0x4a, 0x6f, 0xa0, 0xf4, 0xf5, 0x0c, 0x70, 0x9f, 0x25,
	0x6b, 0x5d, 0xb2, 0x66, 0x57, 0x61, 0x72, 0x57, 0x5d, 0x6d, 0xf5, 0x17, 0x56, 0x56, 0xab, 0x3c,
	0x0e, 0xfe, 0x32, 0xf5, 0xfb, 0x2c, 0x80, 0xd1, 0x3c, 0x78, 0xb3, 0x78, 0x3b, 0xf7, 0xf8, 0x07,
	0x9b, 0xe1, 0x21, 0x74, 0x29, 0xe6, 0x9e, 0x3f, 0x9b, 0x4e, 0x7c, 0xcf, 0xae, 0x21, 0x82, 0xc5,
	0x3d, 0x7f, 0x3a, 0x7e, 0xe7, 0x71, 0x85, 0x1d, 0xe0, 0x03, 0x38, 0xd4, 0x9a, 0x46, 0xeb, 0x68,
	0x83, 0x79, 0x39, 0xbe, 0xf1, 0x26, 0x81, 0x02, 0x1b, 0x78, 0x04, 0x3d, 0xa5, 0x68, 0xac, 0x99,
	0x8b, 0xd7, 0x53, 0xfe, 0x7e, 0xc4, 0xaf, 0x74, 0x4b, 0x03, 0x4f, 0x00, 0xef, 0x45, 0x0d, 0xb7,
	0x72, 0x87, 0x7e, 0x30, 0x7f, 0xa5, 0xb8, 0x76, 0xee, 0x90, 0x62, 0x8d, 0x40, 0x8e, 0x04, 0xd3,
	0xe9, 0x58, 0x21, 0x9d, 0x1c, 0xa1, 0x58, 0x23, 0xe6, 0xf0, 0x14, 0xcc, 0xea, 0xd7, 0xc7, 0x16,
	0xd4, 0x6f, 0x26, 0x5e, 0x60, 0x33, 0x6c, 0x43, 0x23, 0x3f, 0x3d, 0xb7, 0x6b, 0xc3, 0x01, 0x58,
	0xfb, 0x5f, 0x1c, 0x0d, 0x38, 0x98, 0x5f, 0xcd, 0x6c, 0x96, 0x1f, 0x82, 0xcb, 0x99, 0x5d, 0xfb,
	0x17, 0x00, 0x00, 0xff, 0xff, 0xda, 0xce, 0xd6, 0xfb, 0x78, 0x04, 0x00, 0x00,
}
