package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ContextKey is the type to avoid collisions in the context.
type ContextKey string

const (
	StoreIDsKey ContextKey = "storeIDs"
	RolesKey    ContextKey = "roles"
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
func (v *roleValidator) Execute(r *http.Request, claims jwt.MapClaims) error {
	v.claimRoles = []string{}

	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if rolesList, ok := realmAccess["roles"].([]interface{}); ok {
			for _, role := range rolesList {
				v.claimRoles = append(v.claimRoles, role.(string))
			}
		}
	}

	requiredRoles, ok := v.requiredRoles[r.URL.Path]
	if !ok {
		return fmt.Errorf("no roles configured for path: %s", r.URL.Path)
	}

	for _, role := range v.claimRoles {
		for _, requiredRole := range requiredRoles {
			if role == requiredRole {
				return nil // Has access
			}
		}
	}

	return fmt.Errorf("user does not have the required role")
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
func (v *storeIDsValidator) Execute(r *http.Request, claims jwt.MapClaims) error {
	v.claimStoreIDs = []string{}

	storeIDs, ok := claims[storeIDsClaimKey].([]interface{})
	if ok || len(storeIDs) > 0 {
		for _, id := range storeIDs {
			v.claimStoreIDs = append(v.claimStoreIDs, id.(string))
		}
		return nil // Tiene acceso
	}

	return fmt.Errorf("missing store IDs")
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
func (v *allowedOriginValidator) Execute(r *http.Request) error {
	hostAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		hostAddr = r.RemoteAddr // Si falla, usar RemoteAddr directamente
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host // Si falla, usar host directamente
	}

	// Validar si el host pertenece a las fuentes permitidas
	for _, source := range v.allowedSources {
		if strings.HasSuffix(hostAddr, source) || hostAddr == source || strings.HasSuffix(host, source) || host == source {
			return nil // Es un origen permitido
		}
	}

	return errors.New("request is allowed")
}
