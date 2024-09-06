// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.12.4
// source: api/zksnark.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	TronZksnark_CheckZksnarkProof_FullMethodName = "/protocol.TronZksnark/CheckZksnarkProof"
)

// TronZksnarkClient is the client API for TronZksnark service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TronZksnarkClient interface {
	CheckZksnarkProof(ctx context.Context, in *ZksnarkRequest, opts ...grpc.CallOption) (*ZksnarkResponse, error)
}

type tronZksnarkClient struct {
	cc grpc.ClientConnInterface
}

func NewTronZksnarkClient(cc grpc.ClientConnInterface) TronZksnarkClient {
	return &tronZksnarkClient{cc}
}

func (c *tronZksnarkClient) CheckZksnarkProof(ctx context.Context, in *ZksnarkRequest, opts ...grpc.CallOption) (*ZksnarkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ZksnarkResponse)
	err := c.cc.Invoke(ctx, TronZksnark_CheckZksnarkProof_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TronZksnarkServer is the server API for TronZksnark service.
// All implementations must embed UnimplementedTronZksnarkServer
// for forward compatibility.
type TronZksnarkServer interface {
	CheckZksnarkProof(context.Context, *ZksnarkRequest) (*ZksnarkResponse, error)
	mustEmbedUnimplementedTronZksnarkServer()
}

// UnimplementedTronZksnarkServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedTronZksnarkServer struct{}

func (UnimplementedTronZksnarkServer) CheckZksnarkProof(context.Context, *ZksnarkRequest) (*ZksnarkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckZksnarkProof not implemented")
}
func (UnimplementedTronZksnarkServer) mustEmbedUnimplementedTronZksnarkServer() {}
func (UnimplementedTronZksnarkServer) testEmbeddedByValue()                     {}

// UnsafeTronZksnarkServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TronZksnarkServer will
// result in compilation errors.
type UnsafeTronZksnarkServer interface {
	mustEmbedUnimplementedTronZksnarkServer()
}

func RegisterTronZksnarkServer(s grpc.ServiceRegistrar, srv TronZksnarkServer) {
	// If the following call pancis, it indicates UnimplementedTronZksnarkServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&TronZksnark_ServiceDesc, srv)
}

func _TronZksnark_CheckZksnarkProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ZksnarkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TronZksnarkServer).CheckZksnarkProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TronZksnark_CheckZksnarkProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TronZksnarkServer).CheckZksnarkProof(ctx, req.(*ZksnarkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TronZksnark_ServiceDesc is the grpc.ServiceDesc for TronZksnark service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TronZksnark_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "protocol.TronZksnark",
	HandlerType: (*TronZksnarkServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CheckZksnarkProof",
			Handler:    _TronZksnark_CheckZksnarkProof_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/zksnark.proto",
}
