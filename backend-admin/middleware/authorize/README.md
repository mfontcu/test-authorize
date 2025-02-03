# `authorize`

## Introduction

The `authorize` struct provides middlewares/interceptors to manage authorization in applications that use HTTP and gRPC. It implements validations based on JWT tokens and allows defining custom validators to enforce additional rules.

## `authorize`

### Definition

The `authorize` struct manages authorization using a list of validators. These validators are applied to each request to verify user permissions.

### Creating an Instance

To initialize `authorize`, a list of validators must be provided.

```go
authMiddleware := authorize.NewAuthorize(validators)
```

## HTTP Middleware

### Purpose

The HTTP middleware intercepts requests and validates whether the user has permission to access protected resources. It extracts the authorization token, verifies its validity, and applies the security rules defined by the validators. If authorization fails, the request is rejected with a `401 Unauthorized` status.

### Usage

To integrate the middleware into an HTTP server:

```go
http.Handle("/secure", authMiddleware.HTTPMiddleware(http.HandlerFunc(secureHandler)))
```

This ensures that all requests to `/secure` are validated before being processed.

## Authentication with JWT

### Authentication Provider

The `AuthenticationProvider` interface defines a mechanism to authenticate requests using JWT tokens.

```go
type AuthenticationProvider interface {
    Authenticate(ctx context.Context, token string) (context.Context, error)
}
```

### Setting Up Authentication

To integrate authentication into the `authorize` middleware, use `WithAuthentication`:

```go
authProvider := MyJWTAuthProvider{}
authMiddleware := authorize.NewAuthorize(validators, authorize.WithAuthentication(authProvider))
```

## gRPC Interceptor

### Purpose

The gRPC interceptors validate user credentials before allowing access to the server's gRPC services. The authorization token is extracted from the request context, validated, and the rules defined by the validators are applied. If authorization fails, the request is rejected with an `Unauthenticated` error.

### Usage

To protect gRPC services, configure the interceptors in the server:

```go
grpcServer := grpc.NewServer(
	grpc.UnaryInterceptor(authMiddleware.GRPCInterceptor()),
	grpc.StreamInterceptor(authMiddleware.GRPCStreamInterceptor()),
)
```

This ensures that both unary and streaming gRPC calls are validated before execution.

## JWT Token Validation

The `authorize` struct extracts and validates JWT tokens from requests. Custom validators can be defined to apply additional rules.

## Integration with Validators

Validators allow defining specific rules to authorize requests based on the information contained in the JWT token or request metadata. Each validator implements the `FieldValidator` interface and must provide at least two methods:

- `Execute(adapter RequestAdapter, claims jwt.MapClaims) error`: Executes validation on the extracted token claims.
- `AddToContext(ctx context.Context) context.Context`: Adds relevant information to the request context.

### Defining a Custom Validator

A validator can be implemented as follows:

```go
import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"path/to/middleware/authorize"
)

const (
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
```

### Registering Validators

To apply multiple validation rules, different validators can be instantiated and passed to `authorize`:

```go
// Roles
allowedRoles := map[string][]string{
    "/admin": {"super_admin"},
}
roleValidator := NewRoleValidator(allowedRoles)

fieldValidators := []authorize.FieldValidator{
    roleValidator,
}

authorizeMidd := authorize.NewAuthorize(fieldValidators)
```

Each validator will be executed on the request, ensuring that all conditions are met before granting access.

### Usage in HTTP and gRPC

Once registered, validators are automatically integrated into the HTTP middleware and gRPC interceptors without requiring additional configuration.

```go
http.Handle("/admin", authMiddleware.HTTPMiddleware(http.HandlerFunc(adminHandler)))

grpcServer := grpc.NewServer(
	grpc.UnaryInterceptor(authMiddleware.GRPCInterceptor()),
)
```

---

## `allowedOriginWithoutAuthorizeMiddleware`

### Definition

The `allowedOriginWithoutAuthorizeMiddleware` struct provides middleware for handling origin-based validation and bypassing authorization checks for trusted sources.

### Structure

```go
type allowedOriginWithoutAuthorizeMiddleware struct {
	allowedSources []string
}
```

### Creating an Instance

To initialize the middleware, specify a list of allowed origins:

```go
allowedSources := []string{
	"svc.cluster.local", // Domain name for Kubernetes
}

allowedOriginWithoutAuthorizeMidd := authorize.NewAllowedOriginWithoutAuthorizeMiddleware(allowedSources)
```

### HTTP Middleware Integration

The middleware validates incoming requests' origins and allows them to bypass authorization if they match the trusted sources:

```go
http.Handle(
	"/admin", 
	allowedOriginWithoutAuthorizeMidd.HTTPMiddleware(
		authMiddleware.HTTPMiddleware(
			http.HandlerFunc(secureHandler),
		),
	),
)
```

### gRPC Interceptor Integration

For gRPC, the middleware ensures that requests from trusted sources can skip authorization:

```go
grpcServer := grpc.NewServer(
	grpc.ChainUnaryInterceptor(
		allowedOriginWithoutAuthorizeMidd.GRPCInterceptor(),
		authMiddleware.GRPCInterceptor()
	),
	grpc.ChainStreamInterceptor(
		allowedOriginWithoutAuthorizeMidd.GRPCStreamInterceptor(),
		authMiddleware.GRPCStreamInterceptor()
	),
)
```

### Functionality

- Checks if the request’s origin is in the list of allowed sources.
- If the origin is trusted, the request is processed without requiring JWT validation.
- If the origin is not trusted, the request follows normal authorization checks.
