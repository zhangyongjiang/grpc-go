// Code generated by protoc-gen-go. DO NOT EDIT.
// source: blockchain/block_chain.proto

/*
Package blockchain is a generated protocol buffer package.

It is generated from these files:
	blockchain/block_chain.proto

It has these top-level messages:
	Chaininfo
	EmptyMsg
*/
package blockchain

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Chaininfo struct {
	Name   string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Height int32  `protobuf:"varint,2,opt,name=height" json:"height,omitempty"`
}

func (m *Chaininfo) Reset()                    { *m = Chaininfo{} }
func (m *Chaininfo) String() string            { return proto.CompactTextString(m) }
func (*Chaininfo) ProtoMessage()               {}
func (*Chaininfo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Chaininfo) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Chaininfo) GetHeight() int32 {
	if m != nil {
		return m.Height
	}
	return 0
}

type EmptyMsg struct {
}

func (m *EmptyMsg) Reset()                    { *m = EmptyMsg{} }
func (m *EmptyMsg) String() string            { return proto.CompactTextString(m) }
func (*EmptyMsg) ProtoMessage()               {}
func (*EmptyMsg) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func init() {
	proto.RegisterType((*Chaininfo)(nil), "blockchain.Chaininfo")
	proto.RegisterType((*EmptyMsg)(nil), "blockchain.EmptyMsg")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for BlockChain service

type BlockChainClient interface {
	GetChaininfo(ctx context.Context, in *EmptyMsg, opts ...grpc.CallOption) (*Chaininfo, error)
}

type blockChainClient struct {
	cc *grpc.ClientConn
}

func NewBlockChainClient(cc *grpc.ClientConn) BlockChainClient {
	return &blockChainClient{cc}
}

func (c *blockChainClient) GetChaininfo(ctx context.Context, in *EmptyMsg, opts ...grpc.CallOption) (*Chaininfo, error) {
	out := new(Chaininfo)
	err := grpc.Invoke(ctx, "/blockchain.BlockChain/GetChaininfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for BlockChain service

type BlockChainServer interface {
	GetChaininfo(context.Context, *EmptyMsg) (*Chaininfo, error)
}

func RegisterBlockChainServer(s *grpc.Server, srv BlockChainServer) {
	s.RegisterService(&_BlockChain_serviceDesc, srv)
}

func _BlockChain_GetChaininfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmptyMsg)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BlockChainServer).GetChaininfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/blockchain.BlockChain/GetChaininfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BlockChainServer).GetChaininfo(ctx, req.(*EmptyMsg))
	}
	return interceptor(ctx, in, info, handler)
}

var _BlockChain_serviceDesc = grpc.ServiceDesc{
	ServiceName: "blockchain.BlockChain",
	HandlerType: (*BlockChainServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetChaininfo",
			Handler:    _BlockChain_GetChaininfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blockchain/block_chain.proto",
}

func init() { proto.RegisterFile("blockchain/block_chain.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 224 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x49, 0xca, 0xc9, 0x4f,
	0xce, 0x4e, 0xce, 0x48, 0xcc, 0xcc, 0xd3, 0x07, 0x33, 0xe3, 0xc1, 0x6c, 0xbd, 0x82, 0xa2, 0xfc,
	0x92, 0x7c, 0x21, 0x2e, 0x84, 0xac, 0x94, 0x4c, 0x7a, 0x7e, 0x7e, 0x7a, 0x4e, 0xaa, 0x7e, 0x62,
	0x41, 0xa6, 0x7e, 0x62, 0x5e, 0x5e, 0x7e, 0x49, 0x62, 0x49, 0x66, 0x7e, 0x5e, 0x31, 0x44, 0xa5,
	0x92, 0x39, 0x17, 0xa7, 0x33, 0x48, 0x59, 0x66, 0x5e, 0x5a, 0xbe, 0x90, 0x10, 0x17, 0x4b, 0x5e,
	0x62, 0x6e, 0xaa, 0x04, 0xa3, 0x02, 0xa3, 0x06, 0x67, 0x10, 0x98, 0x2d, 0x24, 0xc6, 0xc5, 0x96,
	0x91, 0x9a, 0x99, 0x9e, 0x51, 0x22, 0xc1, 0xa4, 0xc0, 0xa8, 0xc1, 0x1a, 0x04, 0xe5, 0x29, 0x71,
	0x71, 0x71, 0xb8, 0xe6, 0x16, 0x94, 0x54, 0xfa, 0x16, 0xa7, 0x1b, 0x25, 0x72, 0x71, 0x39, 0x81,
	0x2c, 0x04, 0x9b, 0x24, 0x14, 0xcc, 0xc5, 0xe3, 0x9e, 0x5a, 0x82, 0x30, 0x55, 0x44, 0x0f, 0xe1,
	0x1a, 0x3d, 0x98, 0x1e, 0x29, 0x51, 0x64, 0x51, 0xb8, 0x62, 0x25, 0xb1, 0xa6, 0xcb, 0x4f, 0x26,
	0x33, 0x09, 0x28, 0x71, 0xeb, 0x83, 0x65, 0x74, 0x41, 0x82, 0x56, 0x8c, 0x5a, 0x4e, 0x06, 0x5c,
	0xd2, 0x99, 0xf9, 0x7a, 0xe9, 0x45, 0x05, 0xc9, 0x7a, 0xa9, 0x15, 0x89, 0xb9, 0x05, 0x39, 0xa9,
	0xc5, 0x48, 0x06, 0x38, 0xf1, 0x23, 0xec, 0x0f, 0x00, 0xf9, 0x2b, 0x80, 0x31, 0x89, 0x0d, 0xec,
	0x41, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0x39, 0x39, 0xba, 0x53, 0x2a, 0x01, 0x00, 0x00,
}
