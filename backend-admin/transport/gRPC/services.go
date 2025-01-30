package grpcx

import (
	"context"
	"fmt"
	"io"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/mfontcu/backend-admin/middleware/authorize"
	"github.com/mfontcu/backend-admin/pkg/interceptor"
	transportx "github.com/mfontcu/backend-admin/transport"

	pa "github.com/mfontcu/backend-admin/proto"
	pcl "github.com/mfontcu/test-authorize/backend-clerk/proto"
	pc "github.com/mfontcu/test-authorize/backend-client/proto"
)

type ClerkServiceClient interface {
	GetClerks(ctx context.Context, in *pcl.EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pcl.Clerk], error)
}

type ClientServiceClient interface {
	GetClients(ctx context.Context, in *pc.EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pc.Client], error)
}

type AdminServer struct {
	pa.UnimplementedAdminServiceServer
	clerkService  ClerkServiceClient
	clientService ClientServiceClient
}

// NewAdminServer create a new instance of AdminServer
func NewAdminServer(clerkService ClerkServiceClient, clientService ClientServiceClient) *AdminServer {
	// Registry gRPC services
	return &AdminServer{
		UnimplementedAdminServiceServer: pa.UnimplementedAdminServiceServer{},
		clerkService:                    clerkService,
		clientService:                   clientService,
	}
}

func (s *AdminServer) Setup() *grpc.Server {
	// Allowed origins
	allowedSources := []string{
		"localhost",         // Localhost
		"127.0.0.1",         // IP local
		"::1",               // IPv6 local
		"svc.cluster.local", // Domain name for Kubernetes
		"backend-admin",     // Name of the service
	}

	allowedOriginWithoutAuthorizeMidd := authorize.NewAllowedOriginWithoutAuthorizeMiddleware(allowedSources)

	// Roles
	allowedRoles := map[string][]string{
		"/admin.AdminService/GetAdmins":           {"super_admin"},
		"/admin.AdminService/GetClaims":           {"super_admin"},
		"/admin.AdminService/GetClerksFromAdmin":  {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/admin.AdminService/GetClientsFromAdmin": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
	}
	roleValidator := transportx.NewRoleValidator(allowedRoles)

	storeIDsValidator := transportx.NewStoreIDsValidator()

	fieldValidators := []authorize.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}
	authorizeMidd := authorize.NewAuthorize(fieldValidators)

	// Configure gRPC Interceptors
	streamInterceptors := map[string]grpc.StreamServerInterceptor{
		"/admin.AdminService/GetAdmins": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
		"/admin.AdminService/GetClientsFromAdmin": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
		"/admin.AdminService/GetClerksFromAdmin": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
	}

	unaryInterceptors := map[string]grpc.UnaryServerInterceptor{
		"/admin.AdminService/GetClaims": authorizeMidd.GRPCInterceptor(),
	}

	// Create gRPC server with selective middleware
	gRPCServer := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			interceptor.MultiplexorStreamInterceptor(streamInterceptors),
		),
		grpc.ChainUnaryInterceptor(
			interceptor.MultiplexorInterceptor(unaryInterceptors),
		),
		grpc.MaxRecvMsgSize(1024*1024*50), // Aumentar límite de mensaje a 50MB
		grpc.MaxSendMsgSize(1024*1024*50), // Aumentar límite de mensaje a 50MB
	)

	pa.RegisterAdminServiceServer(gRPCServer, s)
	reflection.Register(gRPCServer)

	return gRPCServer
}

func (s *AdminServer) GetAdmins(req *pa.EmptyRequest, stream grpc.ServerStreamingServer[pa.Admin]) error {
	admins := []*pa.Admin{
		{
			ID:   1,
			Name: "Admin 1",
		},
		{
			ID:   2,
			Name: "Admin 2",
		},
	}

	for _, admin := range admins {
		if err := stream.Send(admin); err != nil {
			return err
		}
	}

	return nil
}

func (s *AdminServer) GetClaims(ctx context.Context, req *pa.EmptyRequest) (*pa.ClaimResponse, error) {
	rolesValue := ctx.Value(transportx.RolesKey)
	if rolesValue == nil {
		return nil, fmt.Errorf("user roles not found")
	}

	storeIDsValue := ctx.Value(transportx.StoreIDsKey)
	if storeIDsValue == nil {
		return nil, fmt.Errorf("store IDs not found")
	}

	return &pa.ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}, nil
}

func (s *AdminServer) GetClientsFromAdmin(req *pa.EmptyRequest, stream grpc.ServerStreamingServer[pa.ClientResponse]) error {
	// Request clients from client service
	remoteStream, err := s.clientService.GetClients(context.Background(), &pc.EmptyRequest{})
	if err != nil {
		log.Printf("failed to call remote GetClients: %v", err)
		return err
	}

	// Read clients from client service and send them to the client
	for {
		client, err := remoteStream.Recv()
		if err == io.EOF {
			log.Println("remote stream closed successfully")
			break
		}
		if err != nil {
			log.Printf("error receiving from remote stream: %v", err)
			return err
		}

		response := pa.ClientResponse{
			ID:   client.ID,
			Name: client.Name,
		}

		if err := stream.Send(&response); err != nil {
			log.Printf("error sending client to client: %v", err)
			return err
		}
	}

	return nil
}

func (s *AdminServer) GetClerksFromAdmin(req *pa.EmptyRequest, stream grpc.ServerStreamingServer[pa.ClerkResponse]) error {
	// Request clerks from client service
	remoteStream, err := s.clerkService.GetClerks(context.Background(), &pcl.EmptyRequest{})
	if err != nil {
		log.Printf("failed to call remote GetClerks: %v", err)
		return err
	}

	// Read clerks from client service and send them to the client
	for {
		client, err := remoteStream.Recv()
		if err == io.EOF {
			log.Println("remote stream closed successfully")
			break
		}
		if err != nil {
			log.Printf("error receiving from remote stream: %v", err)
			return err
		}

		response := pa.ClerkResponse{
			ID:   client.ID,
			Name: client.Name,
		}

		if err := stream.Send(&response); err != nil {
			log.Printf("error sending client to client: %v", err)
			return err
		}
	}

	return nil
}
