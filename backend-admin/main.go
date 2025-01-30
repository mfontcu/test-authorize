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

	clientx "github.com/mfontcu/backend-admin/client"
	grpcx "github.com/mfontcu/backend-admin/transport/gRPC"
	httpx "github.com/mfontcu/backend-admin/transport/http"

	pcl "github.com/mfontcu/test-authorize/backend-clerk/proto"
	pc "github.com/mfontcu/test-authorize/backend-client/proto"
)

type Config struct {
	ClerkHost      string `required:"true" envconfig:"CLERK_HOST"`
	ClientHost     string `required:"true" envconfig:"CLIENT_HOST"`
	ClerkgRPCHost  string `required:"true" envconfig:"CLERK_GRPC_HOST"`
	ClientgRPCHost string `required:"true" envconfig:"CLIENT_GRPC_HOST"`
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
	clientClient := clientx.NewClientClient(client, cfg.ClientHost)

	// Create HTTP handlers and setup routes
	httpx.NewAdminHandler(clerkClient, clientClient).Setup(httpRouter)

	httpPort := ":3090"
	go func() {
		log.Printf("server HTTP listening on port %s", httpPort)
		if err := http.ListenAndServe(httpPort, httpRouter); err != nil {
			log.Fatalf("error starting server HTTP: %v", err)
		}
	}()

	// Create gRPC clients
	connClerk, err := grpc.NewClient(cfg.ClerkgRPCHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to create ClerkClient: %v", err)
	}

	connClient, err := grpc.NewClient(cfg.ClientgRPCHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to create ClientClient: %v", err)
	}

	// Create gRPC services
	clerkService := pcl.NewClerkServiceClient(connClerk)
	clientService := pc.NewClientServiceClient(connClient)

	// Create gRPC server
	adminServer := grpcx.NewAdminServer(clerkService, clientService)

	grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stderr, os.Stderr))

	grpcPort := ":50050"
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("failed to start listener on port %s: %v", grpcPort, err)
	}

	log.Printf("server gRPC listening on port %s", grpcPort)
	if err := adminServer.Setup().Serve(listener); err != nil {
		log.Fatalf("error starting server gRPC: %v", err)
	}
}
