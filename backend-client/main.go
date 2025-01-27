package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/kelseyhightower/envconfig"

	"github.com/mfontcu/backend-client/middlewares"
)

type Config struct {
	AdminHost string `required:"true" envconfig:"ADMIN_HOST"`
	ClerkHost string `required:"true" envconfig:"CLERK_HOST"`
}

func Load() (*Config, error) {
	var cfg Config

	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

type Client struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	response := []Client{
		{
			ID:   1,
			Name: "Client 1",
		},
		{
			ID:   2,
			Name: "Client 2",
		},
	}

	log.Println("backend-client")

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

	log.Println("From backend-client to backend-admin")

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

	log.Println("From backend-client to backend-clerk")

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

func liveHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Allowed origins
	allowedSources := []string{
		"localhost",         // Localhost
		"127.0.0.1",         // IP local
		"::1",               // IPv6 local
		"svc.cluster.local", // Domain name for Kubernetes
		"backend-client",    // Name of the service
	}
	allowedOriginValidator := NewAllowedOriginValidator(allowedSources)

	originAllowedValidators := []middlewares.OriginValidator{
		allowedOriginValidator,
	}
	allowedOriginWithoutAuthorizeMidd := middlewares.AllowedOriginWithoutAuthorize(originAllowedValidators)

	// Roles
	allowedRoles := map[string][]string{
		"/client":          {"super_admin"},
		"/client-claim":    {"super_admin"},
		"/client-to-admin": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/client-to-clerk": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
	}
	roleValidator := NewRoleValidator(allowedRoles)

	storeIDsValidator := NewStoreIDsValidator()

	fieldValidators := []middlewares.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}
	authorizeMidd := middlewares.Authorize(fieldValidators)

	r.With(authorizeMidd).Get("/client", clientHandler)
	r.With(authorizeMidd).Get("/client-claim", claimHandler)
	r.With(allowedOriginWithoutAuthorizeMidd, authorizeMidd).Get("/client-to-admin", adminHandler)
	r.With(allowedOriginWithoutAuthorizeMidd, authorizeMidd).Get("/client-to-clerk", clerkHandler)

	r.Get("/live", liveHandler)
	r.Get("/ready", readyHandler)

	log.Println("Server running on port 3092")
	http.ListenAndServe(":3092", r)
}
