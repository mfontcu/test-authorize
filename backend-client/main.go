package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/grpclog"

	"github.com/kelseyhightower/envconfig"

	clientx "github.com/mfontcu/backend-client/client"
	grpcx "github.com/mfontcu/backend-client/transport/gRPC"
	httpx "github.com/mfontcu/backend-client/transport/http"

	pa "github.com/mfontcu/test-authorize/backend-admin/proto"
	pcl "github.com/mfontcu/test-authorize/backend-clerk/proto"
)

type Config struct {
	AdminHost     string `required:"true" envconfig:"ADMIN_HOST"`
	ClerkHost     string `required:"true" envconfig:"CLERK_HOST"`
	AdmingRPCHost string `required:"true" envconfig:"ADMIN_GRPC_HOST"`
	ClerkgRPCHost string `required:"true" envconfig:"CLERK_GRPC_HOST"`
}

func Load() (*Config, error) {
	var cfg Config

	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func main() {
	cfg, err := Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	// Create HTTP router
	httpRouter := chi.NewRouter()
	httpRouter.Use(middleware.Logger)
	httpRouter.Use(middleware.Recoverer)

	// Create HTTP clients
	client := &http.Client{}
	clerkClient := clientx.NewClerkClient(client, cfg.ClerkHost)
	adminClient := clientx.NewAdminClient(client, cfg.AdminHost)

	// Create HTTP handlers and setup routes
	httpx.NewClientHandler(clerkClient, adminClient).Setup(httpRouter)

	httpPort := ":3092"
	go func() {
		log.Printf("server HTTP listening on port %s", httpPort)
		if err := http.ListenAndServe(httpPort, httpRouter); err != nil {
			log.Fatalf("error starting server HTTP: %v", err)
		}
	}()

	// Create gRPC clients
	connClerk, err := grpc.NewClient(cfg.ClerkgRPCHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to create ClientClient: %v", err)
	}

	connAdmin, err := grpc.NewClient(cfg.AdmingRPCHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to create AdminClient: %v", err)
	}

	// Create gRPC services
	clientService := pcl.NewClerkServiceClient(connClerk)
	adminService := pa.NewAdminServiceClient(connAdmin)

	// Create gRPC server
	clientServer := grpcx.NewClientServer(clientService, adminService)

	grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stderr, os.Stderr))

	grpcPort := ":50052"
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("failed to start listener on port %s: %v", grpcPort, err)
	}

	log.Printf("server gRPC listening on port %s", grpcPort)
	if err := clientServer.Setup().Serve(listener); err != nil {
		log.Fatalf("error starting server gRPC: %v", err)
	}
}
