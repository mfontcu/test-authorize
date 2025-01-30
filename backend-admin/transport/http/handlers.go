package httpx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	clientx "github.com/mfontcu/backend-admin/client"
	"github.com/mfontcu/backend-admin/middleware/authorize"

	transportx "github.com/mfontcu/backend-admin/transport"
)

type ClerkService interface {
	GetClerks() ([]clientx.Clerk, error)
}

type ClientService interface {
	GetClients() ([]clientx.Client, error)
}

type AdminHandler struct {
	clerkService  ClerkService
	clientService ClientService
}

func NewAdminHandler(
	clerkService ClerkService,
	clientService ClientService,
) AdminHandler {
	return AdminHandler{
		clerkService,
		clientService,
	}
}

func (h AdminHandler) Setup(mux *chi.Mux) {
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
		"/admin":           {"super_admin"},
		"/admin-claim":     {"super_admin"},
		"/admin-to-clerk":  {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
		"/admin-to-client": {"super_admin", "business_admin", "reatail_admin", "store_management", "store_employee"},
	}
	roleValidator := transportx.NewRoleValidator(allowedRoles)

	storeIDsValidator := transportx.NewStoreIDsValidator()

	fieldValidators := []authorize.FieldValidator{
		roleValidator,
		storeIDsValidator,
	}
	authorizeMidd := authorize.NewAuthorize(fieldValidators)

	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/admin", h.getAdmins)
	mux.With(authorizeMidd.HTTPMiddleware).Get("/admin-claim", h.GetAdminClaim)
	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/admin-to-clerk", h.getClerksFromAdmin)
	mux.With(allowedOriginWithoutAuthorizeMidd.HTTPMiddleware, authorizeMidd.HTTPMiddleware).Get("/admin-to-client", h.getClientsFromAdmin)

	mux.Get("/live", h.liveHandler)
	mux.Get("/ready", h.readyHandler)
}

type Admin struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (h AdminHandler) getAdmins(w http.ResponseWriter, r *http.Request) {
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

func (h AdminHandler) GetAdminClaim(w http.ResponseWriter, r *http.Request) {
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

func (h AdminHandler) getClerksFromAdmin(w http.ResponseWriter, r *http.Request) {
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

func (h AdminHandler) getClientsFromAdmin(w http.ResponseWriter, r *http.Request) {
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

func (h AdminHandler) liveHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h AdminHandler) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
