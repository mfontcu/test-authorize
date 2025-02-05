package grpcx

import (
	"context"
	"fmt"
	"io"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/mfontcu/backend-clerk/middleware/authorize"
	"github.com/mfontcu/backend-clerk/pkg/interceptor"

	transportx "github.com/mfontcu/backend-clerk/transport"

	pcl "github.com/mfontcu/backend-clerk/proto"
	pa "github.com/mfontcu/test-authorize/backend-admin/proto"
	pc "github.com/mfontcu/test-authorize/backend-client/proto"
)

type AdminServiceClient interface {
	GetAdmins(ctx context.Context, in *pa.EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pa.Admin], error)
}

type ClientServiceClient interface {
	GetClients(ctx context.Context, in *pc.EmptyRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pc.Client], error)
}

type ClerkServer struct {
	pcl.UnimplementedClerkServiceServer
	adminService  AdminServiceClient
	clientService ClientServiceClient
}

// NewClerkServer create a new instance of ClerkServer
func NewClerkServer(adminService AdminServiceClient, clientService ClientServiceClient) *ClerkServer {
	// Registry gRPC services
	return &ClerkServer{
		UnimplementedClerkServiceServer: pcl.UnimplementedClerkServiceServer{},
		adminService:                    adminService,
		clientService:                   clientService,
	}
}

func (s *ClerkServer) Setup() *grpc.Server {
	// Allowed origins
	allowedSources := []string{
		"localhost",         // Localhost
		"127.0.0.1",         // IP local
		"::1",               // IPv6 local
		"svc.cluster.local", // Domain name for Kubernetes
		"backend-clerk",     // Name of the service
	}

	allowedOriginWithoutAuthorizeMidd := authorize.NewAllowedOriginWithoutAuthorize(allowedSources)

	// Roles
	allowedRoles := []transportx.AllowedRoles{
		{
			Path:  "/clerk.ClerkService/GetClerks",
			Roles: []string{"super_admin"},
		},
		{
			Path:  "/clerk.ClerkService/GetClaims",
			Roles: []string{"super_admin"},
		},
		{
			Path:  "/clerk.ClerkService/GetAdminsFromClerk",
			Roles: []string{"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		},
		{
			Path:  "/clerk.ClerkService/GetClientsFromClerk",
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
		"/clerk.ClerkService/GetClerks": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
		"/clerk.ClerkService/GetClientsFromClerk": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
		"/clerk.ClerkService/GetAdminsFromClerk": interceptor.ChainStreamInterceptors(
			allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
			authorizeMidd.GRPCStreamInterceptor(),
		),
	}

	unaryInterceptors := map[string]grpc.UnaryServerInterceptor{
		"/clerk.ClerkService/GetClaims": authorizeMidd.GRPCInterceptor(),
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

	pcl.RegisterClerkServiceServer(gRPCServer, s)
	reflection.Register(gRPCServer)

	return gRPCServer
}

func (s *ClerkServer) GetClerks(req *pcl.EmptyRequest, stream grpc.ServerStreamingServer[pcl.Clerk]) error {
	clerks := []*pcl.Clerk{
		{
			ID:   1,
			Name: "Clerk 1",
		},
		{
			ID:   2,
			Name: "Clerk 2",
		},
	}

	for _, clerk := range clerks {
		if err := stream.Send(clerk); err != nil {
			return err
		}
	}

	return nil
}

func (s *ClerkServer) GetClaims(ctx context.Context, req *pcl.EmptyRequest) (*pcl.ClaimResponse, error) {
	rolesValue := ctx.Value(transportx.RolesKey)
	if rolesValue == nil {
		return nil, fmt.Errorf("user roles not found")
	}

	storeIDsValue := ctx.Value(transportx.StoreIDsKey)
	if storeIDsValue == nil {
		return nil, fmt.Errorf("store IDs not found")
	}

	return &pcl.ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}, nil
}

func (s *ClerkServer) GetClientsFromClerk(req *pcl.EmptyRequest, stream grpc.ServerStreamingServer[pcl.ClientResponse]) error {
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

		response := pcl.ClientResponse{
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

func (s *ClerkServer) GetAdminsFromClerk(req *pcl.EmptyRequest, stream grpc.ServerStreamingServer[pcl.AdminResponse]) error {
	// Request clerks from admin service
	remoteStream, err := s.adminService.GetAdmins(context.Background(), &pa.EmptyRequest{})
	if err != nil {
		log.Printf("failed to call remote GetAdmins: %v", err)
		return err
	}

	// Read clerks from admin service and send them to the admin
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

		response := pcl.AdminResponse{
			ID:   admin.ID,
			Name: admin.Name,
		}

		if err := stream.Send(&response); err != nil {
			log.Printf("error sending admin to admin: %v", err)
			return err
		}
	}

	return nil
}
