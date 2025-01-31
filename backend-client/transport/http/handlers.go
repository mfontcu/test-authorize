package httpx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/mfontcu/backend-client/middleware/authorize"

	clientx "github.com/mfontcu/backend-client/client"
	transportx "github.com/mfontcu/backend-client/transport"
)

type ClerkService interface {
	GetClerks() ([]clientx.Clerk, error)
}

type AdminService interface {
	GetAdmins() ([]clientx.Admin, error)
}

type ClientHandler struct {
	clerkService ClerkService
	adminService AdminService
}

func NewClientHandler(
	clerkService ClerkService,
	adminService AdminService,
) ClientHandler {
	return ClientHandler{
		clerkService,
		adminService,
	}
}

func (h ClientHandler) Setup(mux *chi.Mux) {
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
			Path:    "/client",
			Roles:   []string{"super_admin"},
			Methods: []string{http.MethodGet},
		},
		{
			Path:    "/client-claim",
			Roles:   []string{"super_admin"},
			Methods: []string{http.MethodGet},
		},
		{
			Path:    "/client-to-clerk",
			Roles:   []string{"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
			Methods: []string{http.MethodGet},
		},
		{
			Path:    "/client-to-admin",
			Roles:   []string{"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
			Methods: []string{http.MethodGet},
		},
	}
	roleValidator := transportx.NewRoleValidator(allowedRoles)

	storeIDsValidator := transportx.NewStoreIDsValidator()

	fieldValidators := []authorize.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}
	authorizeMidd := authorize.NewAuthorize(fieldValidators)

	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/client", h.getClients)
	mux.With(authorizeMidd.HTTPMiddleware).Get("/client-claim", h.getClientClaim)
	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/client-to-clerk", h.getClerksFromAdmin)
	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/client-to-admin", h.getAdminsFromAdmin)

	mux.Get("/live", h.liveHandler)
	mux.Get("/ready", h.readyHandler)
}

type Client struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (h ClientHandler) getClients(w http.ResponseWriter, r *http.Request) {
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

func (h ClientHandler) getClientClaim(w http.ResponseWriter, r *http.Request) {
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

	log.Println("admin-claim")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// write response json
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h ClientHandler) getClerksFromAdmin(w http.ResponseWriter, r *http.Request) {
	clerks, err := h.clerkService.GetClerks()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get clerks, err: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(clerks); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response, err: %v", err), http.StatusInternalServerError)
	}
}

func (h ClientHandler) getAdminsFromAdmin(w http.ResponseWriter, r *http.Request) {
	clients, err := h.adminService.GetAdmins()
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

func (h ClientHandler) liveHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h ClientHandler) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
