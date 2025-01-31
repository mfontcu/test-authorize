package grpcx

import (
	"context"
	"fmt"
	"io"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/mfontcu/backend-client/middleware/authorize"
	"github.com/mfontcu/backend-client/pkg/interceptor"

	transportx "github.com/mfontcu/backend-client/transport"

	pc "github.com/mfontcu/backend-client/proto"
	pa "github.com/mfontcu/test-authorize/backend-admin/proto"
	pcl "github.com/mfontcu/test-authorize/backend-clerk/proto"
)

type ClerkServiceClient interface {
	GetClerks(ctx context.Context, in *pcl.EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pcl.Clerk], error)
}

type AdminServiceClient interface {
	GetAdmins(ctx context.Context, in *pa.EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pa.Admin], error)
}
type ClientServer struct {
	pc.UnimplementedClientServiceServer
	clerkService ClerkServiceClient
	adminService AdminServiceClient
}

// NewClientServer create a new instance of ClientServer
func NewClientServer(clerkService ClerkServiceClient, adminService AdminServiceClient) *ClientServer {
	// Registry gRPC services
	return &ClientServer{
		UnimplementedClientServiceServer: pc.UnimplementedClientServiceServer{},
		clerkService:                     clerkService,
		adminService:                     adminService,
	}
}

func (s *ClientServer) Setup() *grpc.Server {
	// Allowed origins
	allowedSources := []string{
		"localhost",         // Localhost
		"127.0.0.1",         // IP local
		"::1",               // IPv6 local
		"svc.cluster.local", // Domain name for Kubernetes
		"backend-client",    // Name of the service
	}

	allowedOriginWithoutAuthorizeMidd := authorize.NewAllowedOriginWithoutAuthorizeMiddleware(allowedSources)

	// Roles
	allowedRoles := []transportx.AllowedRoles{
		{
			Path:  "/client.ClientService/GetClients",
			Roles: []string{"super_admin"},
		},
		{
			Path:  "/client.ClientService/GetClaims",
			Roles: []string{"super_admin"},
		},
		{
			Path:  "/client.ClientService/GetClerksFromClient",
			Roles: []string{"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		},
		{
			Path:  "/client.ClientService/GetAdminsFromClient",
			Roles: []string{"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		},
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
		"/client.ClientService/GetClients": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
		"/client.ClientService/GetAdminsFromClient": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
		"/client.ClientService/GetClerksFromClient": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
	}

	unaryInterceptors := map[string]grpc.UnaryServerInterceptor{
		"/client.ClientService/GetClaims": authorizeMidd.GRPCInterceptor(),
	}

	// Create gRPC server with selective middleware
	gRPCServer := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			interceptor.MultiplexorStreamInterceptor(streamInterceptors),
		),
		grpc.ChainUnaryInterceptor(
			interceptor.MultiplexorInterceptor(unaryInterceptors),
		),
	)

	pc.RegisterClientServiceServer(gRPCServer, s)
	reflection.Register(gRPCServer)

	return gRPCServer
}

func (s *ClientServer) GetClients(req *pc.EmptyRequest, stream grpc.ServerStreamingServer[pc.Client]) error {
	clients := []*pc.Client{
		{
			ID:   1,
			Name: "Client 1",
		},
		{
			ID:   2,
			Name: "Client 2",
		},
	}

	for _, client := range clients {
		if err := stream.Send(client); err != nil {
			return err
		}
	}

	return nil
}

func (s *ClientServer) GetClaims(ctx context.Context, req *pc.EmptyRequest) (*pc.ClaimResponse, error) {
	rolesValue := ctx.Value(transportx.RolesKey)
	if rolesValue == nil {
		return nil, fmt.Errorf("user roles not found")
	}

	storeIDsValue := ctx.Value(transportx.StoreIDsKey)
	if storeIDsValue == nil {
		return nil, fmt.Errorf("store IDs not found")
	}

	return &pc.ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}, nil
}

func (s *ClientServer) GetAdminsFromClient(req *pc.EmptyRequest, stream grpc.ServerStreamingServer[pc.AdminResponse]) error {
	// Request admins from admin service
	remoteStream, err := s.adminService.GetAdmins(context.Background(), &pa.EmptyRequest{})
	if err != nil {
		log.Printf("failed to call remote GetAdmins: %v", err)
		return err
	}

	// Read admins from admin service and send them to the admin
	for {
		admin, err := remoteStream.Recv()
		if err == io.EOF {
			log.Println("remote stream closed successfully")
			break
		}
		if err != nil {
			log.Printf("error receiving from remote stream: %v", err)
			return err
		}

		response := pc.AdminResponse{
			ID:   admin.ID,
			Name: admin.Name,
		}

		if err := stream.Send(&response); err != nil {
			log.Printf("error sending client to client: %v", err)
			return err
		}
	}

	return nil
}

func (s *ClientServer) GetClerksFromClient(req *pc.EmptyRequest, stream grpc.ServerStreamingServer[pc.ClerkResponse]) error {
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

		response := pc.ClerkResponse{
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
