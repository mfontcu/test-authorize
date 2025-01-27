package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ContextKey is the type to avoid collisions in the context.
type ContextKey string

const (
	skipAuthorizeKey ContextKey = "skip_auth"
)

// FieldValidator define the interface for request validations.
type FieldValidator interface {
	Execute(r *http.Request, claims jwt.MapClaims) error
	AddToContext(ctx context.Context) context.Context
}

// Authorize middleware for handling authorization.
func Authorize(validators []FieldValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// Validate if the request should be skipped
			if skip, ok := ctx.Value(skipAuthorizeKey).(bool); ok && skip {
				next.ServeHTTP(w, r)
				return
			}

			// Validate the Authorization header
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Extract the claims from the JWT token
			claims, err := extractClaims(tokenString)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Validate the request with all the request validators and add the claims to the context
			for _, v := range validators {
				if err := v.Execute(r, claims); err != nil {
					http.Error(w, fmt.Sprintf("Forbidden: %s", err.Error()), http.StatusForbidden)
					return
				}

				ctx = v.AddToContext(ctx)
			}

			// Delete the Authorization header
			r.Header.Del("Authorization")

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractClaims decode the JWT token and extract the relevant claims.
func extractClaims(tokenString string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token claims")
}

// OriginValidator define the interface for request validations.
type OriginValidator interface {
	Execute(r *http.Request) error
}

// AllowedOriginWithoutAuthorize middleware for handling authorization.
func AllowedOriginWithoutAuthorize(validators []OriginValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Validate the request with all the request validators
			for _, v := range validators {
				if err := v.Execute(r); err == nil {
					// If the request is allowed, skip the authorization
					ctx := context.WithValue(r.Context(), skipAuthorizeKey, true)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
