package transportx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mfontcu/backend-clerk/middleware/authorize"
)

const (
	StoreIDsKey authorize.ContextKey = "storeIDs"
	RolesKey    authorize.ContextKey = "roles"
)

// roleValidator validate if the user has the required roles.
type roleValidator struct {
	requiredRoles map[string][]string // Relation path → required roles.
	claimRoles    []string
}

func NewRoleValidator(requiredRoles map[string][]string) *roleValidator {
	return &roleValidator{
		requiredRoles: requiredRoles,
	}
}

// Validate if the user has the required roles.
func (v *roleValidator) Execute(adapter authorize.RequestAdapter, claims jwt.MapClaims) error {
	v.claimRoles = []string{}

	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if rolesList, ok := realmAccess["roles"].([]interface{}); ok {
			for _, role := range rolesList {
				v.claimRoles = append(v.claimRoles, role.(string))
			}
		}
	}

	urlPath := adapter.GetPath()
	requiredRoles, ok := v.requiredRoles[urlPath]
	if !ok {
		return fmt.Errorf("no roles configured for path: %s", urlPath)
	}

	for _, role := range v.claimRoles {
		for _, requiredRole := range requiredRoles {
			if role == requiredRole {
				return nil // Has access
			}
		}
	}

	return errors.New("missing required roles")
}

func (v roleValidator) AddToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, RolesKey, v.claimRoles)
}

const (
	storeIDsClaimKey = "store_ids"
)

// storeIDsValidator validate that the StoreID is present if necessary.
type storeIDsValidator struct {
	claimStoreIDs []string
}

func NewStoreIDsValidator() *storeIDsValidator {
	return &storeIDsValidator{}
}

// Validate if the user has the required StoreIDs.
func (v *storeIDsValidator) Execute(adapter authorize.RequestAdapter, claims jwt.MapClaims) error {
	v.claimStoreIDs = []string{}

	storeIDs, ok := claims[storeIDsClaimKey].([]interface{})
	if ok || len(storeIDs) > 0 {
		for _, id := range storeIDs {
			v.claimStoreIDs = append(v.claimStoreIDs, id.(string))
		}
		return nil // Tiene acceso
	}

	return errors.New("missing store ID's")
}

func (v storeIDsValidator) AddToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, StoreIDsKey, v.claimStoreIDs)
}

// allowedOriginValidator validate if the request comes from an allowed source.
type allowedOriginValidator struct {
	allowedSources []string // List of allowed sources. (e.g., "localhost", "svc.cluster.local", name of Docker services)
}

// NewAllowedOriginValidator crea un nuevo validador con una lista de fuentes permitidas.
func NewAllowedOriginValidator(allowedSources []string) *allowedOriginValidator {
	return &allowedOriginValidator{
		allowedSources,
	}
}

// Validate if the request comes from an allowed source.
func (v *allowedOriginValidator) Execute(adapter authorize.RequestAdapter) error {
	reqRemoteAddr := adapter.GetRemoteAddr()
	hostAddr, _, err := net.SplitHostPort(reqRemoteAddr)
	if err != nil {
		hostAddr = reqRemoteAddr // If it fails, use the host address directly
	}

	reqHost := adapter.GetHost()
	host, _, err := net.SplitHostPort(reqHost)
	if err != nil {
		host = reqHost // If it fails, use the host directly
	}

	// Validate if the request comes from an allowed source.
	for _, source := range v.allowedSources {
		if strings.HasSuffix(hostAddr, source) || hostAddr == source || strings.HasSuffix(host, source) || host == source {
			return nil // It is allowed
		}
	}

	return errors.New("request is not allowed")
}
