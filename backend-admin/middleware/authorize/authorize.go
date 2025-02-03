package authorize

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ContextKey is the type to avoid collisions in the context.
type ContextKey string

const (
	skipAuthorizeKey ContextKey = "skip_auth"
)

// RequestAdapter define the interface for request adapters.
type RequestAdapter interface {
	Context() context.Context
	GetPath() string
	GetMethod() string
	GetHeader(key string) string
	GetRemoteAddr() string
	GetHost() string
	GetBearerToken() (string, error)
	ShouldSkipAuthorize() bool
	RemoveAuthorization()
}

// FieldValidator define the interface for request validations.
type FieldValidator interface {
	Execute(adapter RequestAdapter, claims jwt.MapClaims) error
	AddToContext(ctx context.Context) context.Context
}

// AuthenticationProvider define the interface for authentication providers.
type AuthenticationProvider interface {
	Authenticate(ctx context.Context, token string) (context.Context, error)
}

// authorize define the middleware for handling authorization.
type authorize struct {
	validators     []FieldValidator
	authentication AuthenticationProvider
}

// NewAuthorize creates a new instance of the Authorize middleware.
func NewAuthorize(
	validators []FieldValidator,
	options ...func(*authorize),
) *authorize {
	authorize := &authorize{
		validators: validators,
	}

	for _, op := range options {
		op(authorize)
	}

	return authorize
}

// WithAuthentication sets the authentication provider for the authorize middleware.
func WithAuthentication(auth AuthenticationProvider) func(*authorize) {
	return func(a *authorize) {
		a.authentication = auth
	}
}

// HTTPMiddleware applies authorization validation for HTTP requests.
func (a *authorize) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adapter := newHTTPRequestAdapter(r)
		ctx, err := a.authorizeRequest(r.Context(), adapter)

		if ctx == nil { // Se omite la autorización y continúa el request
			next.ServeHTTP(w, r)
			return
		}

		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GRPCInterceptor applies authorization validation for gRPC unary requests.
func (a *authorize) GRPCInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		adapter := newGRPCRequestAdapter(ctx, info.FullMethod)
		newCtx, err := a.authorizeRequest(ctx, adapter)

		if newCtx == nil { // Se omite la autorización y continúa el request
			return handler(ctx, req)
		}

		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		return handler(newCtx, req)
	}
}

// GRPCStreamInterceptor applies authorization validation for gRPC streaming requests.
func (a *authorize) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, adapter := ss.Context(), newGRPCRequestAdapter(ss.Context(), info.FullMethod)
		newCtx, err := a.authorizeRequest(ctx, adapter)

		if newCtx == nil { // Omit the authorization and continue the request
			return handler(srv, ss)
		}

		if err != nil {
			return status.Error(codes.Unauthenticated, "unauthorized")
		}

		wrappedStream := newWrapServerStream(ss)
		wrappedStream.WrappedContext = newCtx

		return handler(srv, wrappedStream)
	}
}

// authorizeRequest handles common authorization logic for HTTP and gRPC.
func (a *authorize) authorizeRequest(ctx context.Context, adapter RequestAdapter) (context.Context, error) {
	if adapter.ShouldSkipAuthorize() {
		slog.Log(ctx, slog.LevelInfo, "skipping authorization")
		adapter.RemoveAuthorization()
		return nil, nil // Return nil context to skip authorization
	}

	tokenString, err := adapter.GetBearerToken()
	if err != nil {
		slog.Log(ctx, slog.LevelWarn, err.Error())
		return nil, fmt.Errorf("unauthorized")
	}

	if a.authentication != nil {
		ctx, err = a.authentication.Authenticate(ctx, tokenString)
		if err != nil {
			slog.Log(ctx, slog.LevelWarn, err.Error())
			return nil, fmt.Errorf("unauthorized")
		}
	}

	ctx, err = a.extractAndValidateClaims(adapter, tokenString)
	if err != nil {
		slog.Log(ctx, slog.LevelWarn, err.Error())
		return nil, fmt.Errorf("unauthorized")
	}

	adapter.RemoveAuthorization()
	return ctx, nil
}

// extractAndValidateClaims handles token extraction and validation.
func (a *authorize) extractAndValidateClaims(adapter RequestAdapter, token string) (context.Context, error) {
	claims, err := a.extractClaims(token)
	if err != nil {
		return nil, fmt.Errorf("error extracting claims: %w", err)
	}

	ctx, err := a.validate(adapter, claims)
	if err != nil {
		return nil, fmt.Errorf("error validating claims: %w", err)
	}

	return ctx, nil
}

// extractClaims extract the claims from the JWT token.
func (a *authorize) extractClaims(tokenString string) (jwt.MapClaims, error) {
	// Parse the token without verification
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	// Extract the claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, errors.New("unknown error extracting claims")
}

// validate applies the request validators and adds the claims to the context.
func (a *authorize) validate(adapter RequestAdapter, claims jwt.MapClaims) (context.Context, error) {
	ctx := adapter.Context()
	for _, validator := range a.validators {
		if err := validator.Execute(adapter, claims); err != nil {
			return nil, fmt.Errorf("execution failed: %w", err)
		}
		ctx = validator.AddToContext(ctx)
	}

	return ctx, nil
}

// allowedOriginWithoutAuthorizeMiddleware define the middleware for handling origin validation and skipping authorization.
type allowedOriginWithoutAuthorizeMiddleware struct {
	allowedSources []string
}

// NewAllowedOriginWithoutAuthorizeMiddleware creates a new instance of the allowedOriginWithoutAuthorizeMiddleware middleware.
func NewAllowedOriginWithoutAuthorizeMiddleware(allowedSources []string) *allowedOriginWithoutAuthorizeMiddleware {
	return &allowedOriginWithoutAuthorizeMiddleware{
		allowedSources,
	}
}

// HTTPMiddleware applies origin validation and skips authorization in HTTP requests if the origin is valid.
func (a *allowedOriginWithoutAuthorizeMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adapter := newHTTPRequestAdapter(r)

		if a.validateRequest(adapter) {
			r = r.WithContext(context.WithValue(r.Context(), skipAuthorizeKey, true))
		}

		next.ServeHTTP(w, r)
	})
}

// GRPCInterceptor applies origin validation and skips authorization in gRPC requests if the origin is valid.
func (a *allowedOriginWithoutAuthorizeMiddleware) GRPCInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		adapter := newGRPCRequestAdapter(ctx, info.FullMethod)

		if a.validateRequest(adapter) {
			ctx = context.WithValue(ctx, skipAuthorizeKey, true)
		}

		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor applies origin validation and skips authorization in gRPC streaming services if the origin is valid.
func (a *allowedOriginWithoutAuthorizeMiddleware) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		adapter := newGRPCRequestAdapter(ctx, info.FullMethod)

		if a.validateRequest(adapter) {
			ctx = context.WithValue(ctx, skipAuthorizeKey, true)
			wrappedStream := newWrapServerStream(ss)
			wrappedStream.WrappedContext = ctx

			return handler(srv, wrappedStream)
		}

		return handler(srv, ss)
	}
}

// validateRequest validates if the request comes from an allowed source.
func (a *allowedOriginWithoutAuthorizeMiddleware) validateRequest(adapter RequestAdapter) bool {
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
	for _, source := range a.allowedSources {
		if strings.HasSuffix(hostAddr, source) || hostAddr == source || strings.HasSuffix(host, source) || host == source {
			return true // It is allowed
		}
	}

	return false
}

// httpRequestAdapter implements RequestAdapter for HTTP.
type httpRequestAdapter struct {
	request *http.Request
}

// newHTTPRequestAdapter creates a new instance of the httpRequestAdapter.
func newHTTPRequestAdapter(request *http.Request) *httpRequestAdapter {
	return &httpRequestAdapter{
		request,
	}
}

// Context returns the context of the request.
func (h httpRequestAdapter) Context() context.Context {
	return h.request.Context()
}

// GetPath returns the path of the request.
func (h httpRequestAdapter) GetPath() string {
	return chi.RouteContext(h.request.Context()).RoutePattern()
}

func (h httpRequestAdapter) GetMethod() string {
	return h.request.Method
}

// GetHeader returns the value of the header with the given key.
func (h httpRequestAdapter) GetHeader(key string) string {
	return h.request.Header.Get(key)
}

// GetRemoteAddr returns the remote address of the request.
func (h httpRequestAdapter) GetRemoteAddr() string {
	return h.request.RemoteAddr
}

// GetHost returns the host of the request.
func (h httpRequestAdapter) GetHost() string {
	return h.request.Host
}

// GetBearerToken returns the Bearer token from the Authorization header.
func (h httpRequestAdapter) GetBearerToken() (string, error) {
	authHeader := h.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("missing or invalid authorization header")
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// ShouldSkipAuthorize returns true if the request should skip authorization.
func (h httpRequestAdapter) ShouldSkipAuthorize() bool {
	return h.request.Context().Value(skipAuthorizeKey) == true
}

// RemoveAuthorization removes the Authorization header from the request.
func (h *httpRequestAdapter) RemoveAuthorization() {
	h.request.Header.Del("Authorization")
}

// grpcRequestAdapter implements RequestAdapter for gRPC.
type grpcRequestAdapter struct {
	ctx        context.Context
	fullMethod string // Method name in the format /package.service/method.
}

func newGRPCRequestAdapter(ctx context.Context, fullMethod string) *grpcRequestAdapter {
	return &grpcRequestAdapter{
		ctx,
		fullMethod,
	}
}

// Context returns the context of the request.
func (g grpcRequestAdapter) Context() context.Context {
	return g.ctx
}

// GetPath returns the path of the request.
func (g grpcRequestAdapter) GetPath() string {
	return g.fullMethod
}

func (g grpcRequestAdapter) GetMethod() string {
	return ""
}

// GetHeader returns the value of the header with the given key.
func (g grpcRequestAdapter) GetHeader(key string) string {
	md, ok := metadata.FromIncomingContext(g.ctx)
	if ok && len(md[key]) > 0 {
		return md[key][0]
	}
	return ""
}

// GetRemoteAddr returns the remote address of the request.
func (g grpcRequestAdapter) GetRemoteAddr() string {
	if p, ok := peer.FromContext(g.ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// GetHost returns the host of the request.
func (g grpcRequestAdapter) GetHost() string {
	md, ok := metadata.FromIncomingContext(g.ctx)
	if ok && len(md[":authority"]) > 0 {
		return md[":authority"][0]
	}
	return ""
}

// GetBearerToken returns the Bearer token from the Authorization header.
func (g grpcRequestAdapter) GetBearerToken() (string, error) {
	// Validate the Authorization header
	md, ok := metadata.FromIncomingContext(g.ctx)
	if !ok || len(md["authorization"]) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "missing or invalid authorization header")
	}

	return strings.TrimPrefix(md["authorization"][0], "Bearer "), nil
}

// ShouldSkipAuthorize returns true if the request should skip authorization.
func (g grpcRequestAdapter) ShouldSkipAuthorize() bool {
	skipAuthorize, ok := g.ctx.Value(skipAuthorizeKey).(bool)
	if ok && skipAuthorize {
		return true
	}
	return false
}

// RemoveAuthorization removes the Authorization header from the request.
func (g *grpcRequestAdapter) RemoveAuthorization() {
	md, ok := metadata.FromIncomingContext(g.ctx)
	if !ok {
		return
	}

	mdCopy := md.Copy()
	delete(mdCopy, "authorization")
	g.ctx = metadata.NewIncomingContext(g.ctx, mdCopy)
}

// wrapServerStream wraps the gRPC server stream with a modified context.
type wrappedServerStream struct {
	grpc.ServerStream
	WrappedContext context.Context
}

// newWrapServerStream creates a new instance of the wrappedServerStream.
func newWrapServerStream(stream grpc.ServerStream) *wrappedServerStream {
	return &wrappedServerStream{
		ServerStream:   stream,
		WrappedContext: stream.Context(),
	}
}

// Context returns the modified context.
func (w *wrappedServerStream) Context() context.Context {
	return w.WrappedContext
}
