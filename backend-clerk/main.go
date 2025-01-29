package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"google.golang.org/grpc"

	"github.com/kelseyhightower/envconfig"

	"github.com/mfontcu/backend-clerk/middleware/authorize"
	"github.com/mfontcu/backend-clerk/pkg/interceptor"

	pc "github.com/mfontcu/backend-clerk/proto"
)

type Config struct {
	AdminHost  string `required:"true" envconfig:"ADMIN_HOST"`
	ClientHost string `required:"true" envconfig:"CLIENT_HOST"`
}

func Load() (*Config, error) {
	var cfg Config

	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

type Clerk struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func clerkHandler(w http.ResponseWriter, r *http.Request) {
	response := []Clerk{
		{
			ID:   1,
			Name: "Clerk 1",
		},
		{
			ID:   2,
			Name: "Clerk 2",
		},
	}

	log.Println("backend-clerk")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// write response json
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type ClaimResponse struct {
	Message  string   `json:"message"`
	Roles    []string `json:"roles"`
	StoreIDs []string `json:"storeIDs"`
}

func claimHandler(w http.ResponseWriter, r *http.Request) {
	rolesValue := r.Context().Value(RolesKey)
	if rolesValue == nil {
		http.Error(w, "User roles not found", http.StatusUnauthorized)
		return
	}

	storeIDsValue := r.Context().Value(StoreIDsKey)
	if storeIDsValue == nil {
		http.Error(w, "User roles not found", http.StatusUnauthorized)
		return
	}

	response := ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}

	log.Println("admin-claim")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// write response json
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Admin struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	cfg, err := Load()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load configuration, err: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("From backend-clerk to backend-admin")

	res, err := http.Get(cfg.AdminHost + "/admin")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get response from admin service, err: %v", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to get response from admin service, status code: %v", res.StatusCode), http.StatusInternalServerError)
		return
	}

	var admin []Admin
	err = json.NewDecoder(res.Body).Decode(&admin)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode response, err: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(admin); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response, err: %v", err), http.StatusInternalServerError)
	}
}

type Client struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	cfg, err := Load()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load configuration, err: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("From backend-clerk to backend-client")

	res, err := http.Get(cfg.ClientHost + "/client")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get response from client service, err: %v", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to get response from client service, status code: %v", res.StatusCode), http.StatusInternalServerError)
		return
	}

	var client []Client
	err = json.NewDecoder(res.Body).Decode(&client)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode response, err: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(client); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response, err: %v", err), http.StatusInternalServerError)
	}
}

func liveHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Implementación del servidor gRPC
type ClerkServer struct {
	pc.UnimplementedClerkServiceServer
}

func (s *ClerkServer) GetClerks(req *pc.EmptyRequest, stream grpc.ServerStreamingServer[pc.Clerk]) error {
	clerks := []*pc.Clerk{
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

func (s *ClerkServer) GetClaims(ctx context.Context, req *pc.EmptyRequest) (*pc.ClaimResponse, error) {
	rolesValue := ctx.Value(RolesKey)
	if rolesValue == nil {
		return nil, fmt.Errorf("user roles not found")
	}

	storeIDsValue := ctx.Value(StoreIDsKey)
	if storeIDsValue == nil {
		return nil, fmt.Errorf("store IDs not found")
	}

	return &pc.ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}, nil
}

func (s *ClerkServer) GetClientsFromClient(req *pc.EmptyRequest, stream grpc.ServerStreamingServer[pc.ClientResponse]) error {
	return nil
}

func (s *ClerkServer) GetAdminsFromClient(req *pc.EmptyRequest, stream grpc.ServerStreamingServer[pc.AdminResponse]) error {
	return nil
}

func main() {
	httpRouter := chi.NewRouter()

	httpRouter.Use(middleware.Logger)
	httpRouter.Use(middleware.Recoverer)

	// Allowed origins
	allowedSources := []string{
		"localhost",         // Localhost
		"127.0.0.1",         // IP local
		"::1",               // IPv6 local
		"svc.cluster.local", // Domain name for Kubernetes
		"backend-clerk",     // Name of the service
	}
	allowedOriginWithoutAuthorizeMidd := authorize.NewAllowedOriginWithoutAuthorizeMiddleware(allowedSources)

	// Roles
	allowedRoles := map[string][]string{
		"/clerk":                                  {"super_admin"},
		"/clerk-claim":                            {"super_admin"},
		"/clerk-to-admin":                         {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/clerk-to-client":                        {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/clerk.ClerkService/GetClerks":           {"super_admin"},
		"/clerk.ClerkService/GetClaims":           {"super_admin"},
		"/clerk.ClerkService/GetAdminsFromClerk":  {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/clerk.ClerkService/GetClientsFromClerk": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
	}
	roleValidator := NewRoleValidator(allowedRoles)

	storeIDsValidator := NewStoreIDsValidator()

	fieldValidators := []authorize.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}

	authorizeMidd := authorize.NewAuthorize(fieldValidators)

	httpRouter.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/clerk", clerkHandler)
	httpRouter.With(authorizeMidd.HTTPMiddleware).Get("/clerk-claim", claimHandler)
	httpRouter.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/clerk-to-admin", adminHandler)
	httpRouter.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/clerk-to-client", clientHandler)

	httpRouter.Get("/live", liveHandler)
	httpRouter.Get("/ready", readyHandler)

	httpPort := ":3091"
	go func() {
		log.Printf("Servidor HTTP escuchando en %s", httpPort)
		if err := http.ListenAndServe(httpPort, httpRouter); err != nil {
			log.Fatalf("Error iniciando servidor HTTP: %v", err)
		}
	}()

	// Configure gRPC Interceptors
	streamInterceptors := map[string]grpc.StreamServerInterceptor{
		"/clerk.ClerkService/GetClerks": authorizeMidd.GRPCStreamInterceptor(),
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
	grpcServer := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			interceptor.MultiplexorStreamInterceptor(streamInterceptors),
		),
		grpc.ChainUnaryInterceptor(
			interceptor.MultiplexorInterceptor(unaryInterceptors),
		),
	)

	// Registry gRPC services
	pc.RegisterClerkServiceServer(grpcServer, &ClerkServer{})

	grpcPort := ":50051"
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Error al iniciar listener en el puerto %s: %v", grpcPort, err)
	}

	log.Printf("Servidor gRPC escuchando en %s", grpcPort)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Error iniciando servidor gRPC: %v", err)
	}
}
