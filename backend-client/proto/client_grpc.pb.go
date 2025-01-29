// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: client.proto

package client

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
	ClientService_GetClients_FullMethodName          = "/client.ClientService/GetClients"
	ClientService_GetClaims_FullMethodName           = "/client.ClientService/GetClaims"
	ClientService_GetAdminsFromClient_FullMethodName = "/client.ClientService/GetAdminsFromClient"
	ClientService_GetClerksFromClient_FullMethodName = "/client.ClientService/GetClerksFromClient"
)

// ClientServiceClient is the client API for ClientService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ClientServiceClient interface {
	GetClients(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Client], error)
	GetClaims(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (*ClaimResponse, error)
	GetAdminsFromClient(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[AdminResponse], error)
	GetClerksFromClient(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[ClerkResponse], error)
}

type clientServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewClientServiceClient(cc grpc.ClientConnInterface) ClientServiceClient {
	return &clientServiceClient{cc}
}

func (c *clientServiceClient) GetClients(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Client], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClientService_ServiceDesc.Streams[0], ClientService_GetClients_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[EmptyRequest, Client]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClientService_GetClientsClient = grpc.ServerStreamingClient[Client]

func (c *clientServiceClient) GetClaims(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (*ClaimResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ClaimResponse)
	err := c.cc.Invoke(ctx, ClientService_GetClaims_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientServiceClient) GetAdminsFromClient(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[AdminResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClientService_ServiceDesc.Streams[1], ClientService_GetAdminsFromClient_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[EmptyRequest, AdminResponse]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClientService_GetAdminsFromClientClient = grpc.ServerStreamingClient[AdminResponse]

func (c *clientServiceClient) GetClerksFromClient(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[ClerkResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ClientService_ServiceDesc.Streams[2], ClientService_GetClerksFromClient_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[EmptyRequest, ClerkResponse]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClientService_GetClerksFromClientClient = grpc.ServerStreamingClient[ClerkResponse]

// ClientServiceServer is the server API for ClientService service.
// All implementations must embed UnimplementedClientServiceServer
// for forward compatibility.
type ClientServiceServer interface {
	GetClients(*EmptyRequest, grpc.ServerStreamingServer[Client]) error
	GetClaims(context.Context, *EmptyRequest) (*ClaimResponse, error)
	GetAdminsFromClient(*EmptyRequest, grpc.ServerStreamingServer[AdminResponse]) error
	GetClerksFromClient(*EmptyRequest, grpc.ServerStreamingServer[ClerkResponse]) error
	mustEmbedUnimplementedClientServiceServer()
}

// UnimplementedClientServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedClientServiceServer struct{}

func (UnimplementedClientServiceServer) GetClients(*EmptyRequest, grpc.ServerStreamingServer[Client]) error {
	return status.Errorf(codes.Unimplemented, "method GetClients not implemented")
}
func (UnimplementedClientServiceServer) GetClaims(context.Context, *EmptyRequest) (*ClaimResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetClaims not implemented")
}
func (UnimplementedClientServiceServer) GetAdminsFromClient(*EmptyRequest, grpc.ServerStreamingServer[AdminResponse]) error {
	return status.Errorf(codes.Unimplemented, "method GetAdminsFromClient not implemented")
}
func (UnimplementedClientServiceServer) GetClerksFromClient(*EmptyRequest, grpc.ServerStreamingServer[ClerkResponse]) error {
	return status.Errorf(codes.Unimplemented, "method GetClerksFromClient not implemented")
}
func (UnimplementedClientServiceServer) mustEmbedUnimplementedClientServiceServer() {}
func (UnimplementedClientServiceServer) testEmbeddedByValue()                       {}

// UnsafeClientServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ClientServiceServer will
// result in compilation errors.
type UnsafeClientServiceServer interface {
	mustEmbedUnimplementedClientServiceServer()
}

func RegisterClientServiceServer(s grpc.ServiceRegistrar, srv ClientServiceServer) {
	// If the following call pancis, it indicates UnimplementedClientServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ClientService_ServiceDesc, srv)
}

func _ClientService_GetClients_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(EmptyRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClientServiceServer).GetClients(m, &grpc.GenericServerStream[EmptyRequest, Client]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClientService_GetClientsServer = grpc.ServerStreamingServer[Client]

func _ClientService_GetClaims_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmptyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServiceServer).GetClaims(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ClientService_GetClaims_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServiceServer).GetClaims(ctx, req.(*EmptyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClientService_GetAdminsFromClient_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(EmptyRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClientServiceServer).GetAdminsFromClient(m, &grpc.GenericServerStream[EmptyRequest, AdminResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClientService_GetAdminsFromClientServer = grpc.ServerStreamingServer[AdminResponse]

func _ClientService_GetClerksFromClient_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(EmptyRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClientServiceServer).GetClerksFromClient(m, &grpc.GenericServerStream[EmptyRequest, ClerkResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ClientService_GetClerksFromClientServer = grpc.ServerStreamingServer[ClerkResponse]

// ClientService_ServiceDesc is the grpc.ServiceDesc for ClientService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ClientService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "client.ClientService",
	HandlerType: (*ClientServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetClaims",
			Handler:    _ClientService_GetClaims_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetClients",
			Handler:       _ClientService_GetClients_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetAdminsFromClient",
			Handler:       _ClientService_GetAdminsFromClient_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetClerksFromClient",
			Handler:       _ClientService_GetClerksFromClient_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "client.proto",
}
