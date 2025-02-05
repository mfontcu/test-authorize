package transportx

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mfontcu/backend-client/middleware/authorize"
)

const (
	StoreIDsKey authorize.ContextKey = "storeIDs"
	RolesKey    authorize.ContextKey = "roles"
)

type AllowedRoles struct {
	Path    string
	Methods []string
	Roles   []string
}

// roleValidator validate if the user has the required roles.
type roleValidator struct {
	requiredRoles []AllowedRoles // Relation path → required roles.
	claimRoles    []string
}

func NewRoleValidator(requiredRoles []AllowedRoles) *roleValidator {
	return &roleValidator{
		requiredRoles: requiredRoles,
	}
}

// Validate if the user has the required roles.
func (v *roleValidator) Execute(adapter authorize.RequestAdapter, claims jwt.MapClaims) error {
	v.claimRoles = extractRoles(claims)

	urlPath, method := adapter.GetPath(), adapter.GetMethod()
	isGRPC := isGRPCRequest(adapter)

	for _, allowedRoles := range v.requiredRoles {
		if urlPath != allowedRoles.Path {
			continue
		}

		if isGRPC || slices.Contains(allowedRoles.Methods, method) {
			if hasRequiredRole(v.claimRoles, allowedRoles.Roles) {
				return nil // Has access
			}
		}
	}

	return fmt.Errorf("no roles configured for path %s", urlPath)
}

func (v roleValidator) AddToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, RolesKey, v.claimRoles)
}

// Extract roles from JWT claims.
func extractRoles(claims jwt.MapClaims) []string {
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if rolesList, ok := realmAccess["roles"].([]interface{}); ok {
			roles := make([]string, len(rolesList))
			for i, role := range rolesList {
				roles[i] = role.(string)
			}
			return roles
		}
	}
	return nil
}

// Detects if the request is gRPC based on headers or path format.
func isGRPCRequest(adapter authorize.RequestAdapter) bool {
	// Check Content-Type header
	if adapter.GetHeader("Content-Type") == "application/grpc" {
		return true
	}

	// gRPC requests often have paths in the form of /package.service/method
	urlPath := adapter.GetPath()
	return strings.Contains(urlPath, ".") && strings.HasPrefix(urlPath, "/")
}

// Check if the user has at least one required role.
func hasRequiredRole(userRoles, requiredRoles []string) bool {
	roleSet := make(map[string]struct{}, len(userRoles))
	for _, role := range userRoles {
		roleSet[role] = struct{}{}
	}
	for _, requiredRole := range requiredRoles {
		if _, exists := roleSet[requiredRole]; exists {
			return true
		}
	}
	return false
}

const (
	storeIDsClaimKey = "store_ids"
)

// storeIDsValidator validate that the StoreID is present if necessary.
type storeIDsValidator struct {
	claimStoreIDs []string
}

// NewStoreIDsValidator creates a new instance of storeIDsValidator.
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
		return nil // Has access
	}

	return errors.New("missing store ID's")
}

func (v storeIDsValidator) AddToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, StoreIDsKey, v.claimStoreIDs)
}
