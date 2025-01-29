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

	"github.com/mfontcu/backend-admin/middleware/authorize"
	"github.com/mfontcu/backend-admin/pkg/interceptor"

	pa "github.com/mfontcu/backend-admin/proto"
)

type Config struct {
	ClerkHost  string `required:"true" envconfig:"CLERK_HOST"`
	ClientHost string `required:"true" envconfig:"CLIENT_HOST"`
}

func Load() (*Config, error) {
	var cfg Config

	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

type Admin struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	response := []Admin{
		{
			ID:   1,
			Name: "Admin 1",
		},
		{
			ID:   2,
			Name: "Admin 2",
		},
	}

	log.Println("backend-admin")

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

type Clerk struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func clerkHandler(w http.ResponseWriter, r *http.Request) {
	cfg, err := Load()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load configuration, err: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("From backend-admin to backend-clerk")

	res, err := http.Get(cfg.ClerkHost + "/clerk")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get response from clerk service, err: %v", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to get response from clerk service, status code: %v", res.StatusCode), http.StatusInternalServerError)
		return
	}

	var clerk []Clerk
	err = json.NewDecoder(res.Body).Decode(&clerk)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode response, err: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(clerk); err != nil {
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

	log.Println("From backend-admin to backend-client")

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

type AdminServer struct {
	pa.UnimplementedAdminServiceServer
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
	rolesValue := ctx.Value(RolesKey)
	if rolesValue == nil {
		return nil, fmt.Errorf("user roles not found")
	}

	storeIDsValue := ctx.Value(StoreIDsKey)
	if storeIDsValue == nil {
		return nil, fmt.Errorf("store IDs not found")
	}

	return &pa.ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}, nil
}

func (s *AdminServer) GetClientsFromClient(req *pa.EmptyRequest, stream grpc.ServerStreamingServer[pa.ClientResponse]) error {
	return nil
}

func (s *AdminServer) GetClerksFromClient(req *pa.EmptyRequest, stream grpc.ServerStreamingServer[pa.ClerkResponse]) error {
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
		"backend-admin",     // Name of the service
	}
	allowedOriginWithoutAuthorizeMidd := authorize.NewAllowedOriginWithoutAuthorizeMiddleware(allowedSources)

	// Roles
	allowedRoles := map[string][]string{
		"/admin":                                  {"super_admin"},
		"/admin-claim":                            {"super_admin"},
		"/admin-to-clerk":                         {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/admin-to-client":                        {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/admin.AdminService/GetAdmins":           {"super_admin"},
		"/admin.AdminService/GetClaims":           {"super_admin"},
		"/admin.AdminService/GetClerksFromAdmin":  {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/admin.AdminService/GetClientsFromAdmin": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
	}
	roleValidator := NewRoleValidator(allowedRoles)

	storeIDsValidator := NewStoreIDsValidator()

	fieldValidators := []authorize.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}
	authorizeMidd := authorize.NewAuthorize(fieldValidators)

	httpRouter.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/admin", adminHandler)
	httpRouter.With(authorizeMidd.HTTPMiddleware).Get("/admin-claim", claimHandler)
	httpRouter.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/admin-to-clerk", clerkHandler)
	httpRouter.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/admin-to-client", clientHandler)

	httpRouter.Get("/live", liveHandler)
	httpRouter.Get("/ready", readyHandler)

	httpPort := ":3090"
	go func() {
		log.Printf("Servidor HTTP escuchando en %s", httpPort)
		if err := http.ListenAndServe(httpPort, httpRouter); err != nil {
			log.Fatalf("Error iniciando servidor HTTP: %v", err)
		}
	}()

	// Configure gRPC Interceptors
	streamInterceptors := map[string]grpc.StreamServerInterceptor{
		"/admin.AdminService/GetAdmins": authorizeMidd.GRPCStreamInterceptor(),
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
	grpcServer := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			interceptor.MultiplexorStreamInterceptor(streamInterceptors),
		),
		grpc.ChainUnaryInterceptor(
			interceptor.MultiplexorInterceptor(unaryInterceptors),
		),
	)

	// Registry gRPC services
	pa.RegisterAdminServiceServer(grpcServer, &AdminServer{})

	grpcPort := ":50050"
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Error al iniciar listener en el puerto %s: %v", grpcPort, err)
	}

	log.Printf("Servidor gRPC escuchando en %s", grpcPort)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Error iniciando servidor gRPC: %v", err)
	}
}
