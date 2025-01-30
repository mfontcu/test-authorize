package httpx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	clientx "github.com/mfontcu/backend-clerk/client"
	transportx "github.com/mfontcu/backend-clerk/transport"

	"github.com/mfontcu/backend-clerk/middleware/authorize"
)

type AdminService interface {
	GetAdmins() ([]clientx.Admin, error)
}

type ClientService interface {
	GetClients() ([]clientx.Client, error)
}

type ClerkHandler struct {
	adminService  AdminService
	clientService ClientService
}

func NewClerkHandler(
	adminService AdminService,
	clientService ClientService,
) ClerkHandler {
	return ClerkHandler{
		adminService,
		clientService,
	}
}

func (h ClerkHandler) Setup(mux *chi.Mux) {
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
		"/clerk":           {"super_admin"},
		"/clerk-claim":     {"super_admin"},
		"/clerk-to-admin":  {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/clerk-to-client": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
	}
	roleValidator := transportx.NewRoleValidator(allowedRoles)

	storeIDsValidator := transportx.NewStoreIDsValidator()

	fieldValidators := []authorize.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}
	authorizeMidd := authorize.NewAuthorize(fieldValidators)

	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/clerk", h.getClerks)
	mux.With(authorizeMidd.HTTPMiddleware).Get("/clerk-claim", h.getClerkClaim)
	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/clerk-to-admin", h.getAdminsFromAdmin)
	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/clerk-to-client", h.getClientsFromAdmin)

	mux.Get("/live", h.liveHandler)
	mux.Get("/ready", h.readyHandler)
}

type Clerk struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (h ClerkHandler) getClerks(w http.ResponseWriter, r *http.Request) {
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

func (h ClerkHandler) getClerkClaim(w http.ResponseWriter, r *http.Request) {
	rolesValue := r.Context().Value(transportx.RolesKey)
	if rolesValue == nil {
		http.Error(w, "user roles not found", http.StatusUnauthorized)
		return
	}

	storeIDsValue := r.Context().Value(transportx.StoreIDsKey)
	if storeIDsValue == nil {
		http.Error(w, "user roles not found", http.StatusUnauthorized)
		return
	}

	response := ClaimResponse{
		Message:  "Request successful",
		Roles:    rolesValue.([]string),
		StoreIDs: storeIDsValue.([]string),
	}

	log.Println("clerk-claim")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// write response json
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h ClerkHandler) getAdminsFromAdmin(w http.ResponseWriter, r *http.Request) {
	admins, err := h.adminService.GetAdmins()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get admins, err: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(admins); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response, err: %v", err), http.StatusInternalServerError)
	}
}

func (h ClerkHandler) getClientsFromAdmin(w http.ResponseWriter, r *http.Request) {
	clients, err := h.clientService.GetClients()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get clients, err: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(clients); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response, err: %v", err), http.StatusInternalServerError)
	}
}

func (h ClerkHandler) liveHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h ClerkHandler) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
