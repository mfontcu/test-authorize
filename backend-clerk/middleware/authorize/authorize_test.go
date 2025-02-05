package authorize

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockFieldValidator struct {
	mock.Mock
}

func (m *mockFieldValidator) Execute(adapter RequestAdapter, claims jwt.MapClaims) error {
	args := m.Called(adapter, claims)
	return args.Error(0)
}

func (m *mockFieldValidator) AddToContext(ctx context.Context) context.Context {
	args := m.Called(ctx)
	return args.Get(0).(context.Context)
}

func Test_NewAuthorize(t *testing.T) {
	mockRoleValidator := &mockFieldValidator{}
	mockStoreIDsValidator := &mockFieldValidator{}

	type args struct {
		validators []FieldValidator
		options    []func(*authorize)
	}

	tests := map[string]struct {
		args args
		want *authorize
	}{
		"when instantiating a new authorize, should return a new instance": {
			args: args{
				validators: []FieldValidator{
					mockRoleValidator,
					mockStoreIDsValidator,
				},
				options: []func(a *authorize){
					func(a *authorize) {
						a.authentication = AuthenticationProvider(nil)
					},
				},
			},
			want: &authorize{
				validators: []FieldValidator{
					mockRoleValidator,
					mockStoreIDsValidator,
				},
				authentication: nil,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := NewAuthorize(tt.args.validators, tt.args.options...)

			assert.Equal(t, tt.want, got)
		})
	}
}

type mockAuthenticationProvider struct {
	mock.Mock
}

func (m *mockAuthenticationProvider) Authenticate(ctx context.Context, token string) (context.Context, error) {
	args := m.Called(ctx, token)
	if args.Get(0) != nil {
		return args.Get(0).(context.Context), args.Error(1)
	}
	return nil, args.Error(1)
}

func Test_WithAuthentication(t *testing.T) {
	type args struct {
		authentication AuthenticationProvider
	}

	tests := map[string]struct {
		args args
		want *authorize
	}{
		"should assign authentication provider": {
			args: args{
				authentication: &mockAuthenticationProvider{},
			},
			want: &authorize{
				authentication: &mockAuthenticationProvider{},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := NewAuthorize(
				nil,
				WithAuthentication(tt.args.authentication),
			)

			assert.Equal(t, tt.want.authentication, a.authentication)
		})
	}
}

func Test_NewAuthorize_HTTPMiddleware(t *testing.T) {
	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"fake_attr": []string{"fake_value"},
	})
	tokenWithClaimsString, _ := tokenWithClaims.SignedString([]byte("my_secret_key"))

	type args struct {
		next http.Handler
		req  *http.Request
	}

	tests := []struct {
		name           string
		buildAuthorize func() *authorize
		args           args
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "authorization skipped",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					ctx := context.WithValue(req.Context(), skipAuthorizeKey, true)
					return req.WithContext(ctx)
				}(),
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "next handler",
		},
		{
			name: "invalid barer token",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization", "token")

					return req
				}(),
			},
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       "unauthorized\n",
		},
		{
			name: "authenticate fails",
			buildAuthorize: func() *authorize {
				m := &mockAuthenticationProvider{}
				m.On("Authenticate", context.Background(), mock.Anything).Return(nil, assert.AnError).Once()

				return &authorize{
					authentication: m,
				}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization",
						fmt.Sprintf("Bearer %s", "invalid-token"),
					)
					return req
				}(),
			},
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       "unauthorized\n",
		},
		{
			name: "extract claims fails",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization",
						fmt.Sprintf("Bearer %s", "invalid-token"),
					)
					return req
				}(),
			},
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       "unauthorized\n",
		},
		{
			name: "validations fails",
			buildAuthorize: func() *authorize {
				m := &mockFieldValidator{}
				m.On("Execute", mock.Anything, mock.Anything).Return(assert.AnError).Once()

				return &authorize{
					validators: []FieldValidator{
						m,
					},
				}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization",
						fmt.Sprintf("Bearer %s", tokenWithClaimsString),
					)
					return req
				}(),
			},
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       "unauthorized\n",
		},
		{
			name: "authorization succeeds",
			buildAuthorize: func() *authorize {
				m := &mockFieldValidator{}
				m.On("Execute", mock.Anything, mock.Anything).Return(nil).Once()
				m.On("AddToContext", mock.Anything).Return(context.Background()).Once()

				return &authorize{
					validators: []FieldValidator{
						m,
					},
				}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization",
						fmt.Sprintf("Bearer %s", tokenWithClaimsString),
					)
					return req
				}(),
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "next handler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the mock
			authorize := tt.buildAuthorize()

			// Create the middleware
			middleware := authorize.HTTPMiddleware(tt.args.next)

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			middleware.ServeHTTP(rr, tt.args.req)

			// Check the status code
			assert.Equal(t, tt.wantStatusCode, rr.Code)

			// Check the response body
			assert.Equal(t, tt.wantBody, rr.Body.String())
		})
	}
}

func Test_NewAuthorize_GRPCInterceptor(t *testing.T) {
	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"fake_attr": []string{"fake_value"},
	})
	tokenWithClaimsString, _ := tokenWithClaims.SignedString([]byte("my_secret_key"))

	type args struct {
		ctx     context.Context
		req     interface{}
		info    *grpc.UnaryServerInfo
		handler grpc.UnaryHandler
	}

	tests := []struct {
		name           string
		buildAuthorize func() *authorize
		args           args
		wantErr        bool
		wantErrCode    codes.Code
	}{
		{
			name: "authorization skipped",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				ctx: context.WithValue(context.Background(), skipAuthorizeKey, true),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr: false,
		},
		{
			name: "invalid bearer token",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "token")),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name: "authenticate fails",
			buildAuthorize: func() *authorize {
				m := &mockAuthenticationProvider{}
				m.On("Authenticate", mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
				return &authorize{authentication: m}
			},
			args: args{
				ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid-token")),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name: "authorization succeeds",
			buildAuthorize: func() *authorize {
				m := &mockFieldValidator{}
				m.On("Execute", mock.Anything, mock.Anything).Return(nil).Once()
				m.On("AddToContext", mock.Anything).Return(context.Background()).Once()
				return &authorize{
					validators: []FieldValidator{m},
				}
			},
			args: args{
				ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenWithClaimsString)),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorize := tt.buildAuthorize()
			interceptor := authorize.GRPCInterceptor()
			_, err := interceptor(tt.args.ctx, tt.args.req, tt.args.info, tt.args.handler)

			if tt.wantErr {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, tt.wantErrCode, st.Code())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func Test_NewAuthorize_GRPCStreamInterceptor(t *testing.T) {
	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"fake_attr": []string{"fake_value"},
	})
	tokenWithClaimsString, _ := tokenWithClaims.SignedString([]byte("my_secret_key"))

	type args struct {
		ss      grpc.ServerStream
		info    *grpc.StreamServerInfo
		handler grpc.StreamHandler
	}

	tests := []struct {
		name           string
		buildAuthorize func() *authorize
		args           args
		wantErr        bool
		wantErrCode    codes.Code
	}{
		{
			name: "authorization skipped",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				ss: &mockServerStream{
					ctx: context.WithValue(context.Background(), skipAuthorizeKey, true),
				},
				info: &grpc.StreamServerInfo{
					FullMethod: "/test.Service/StreamMethod",
				},
				handler: func(srv interface{}, ss grpc.ServerStream) error {
					return nil
				},
			},
			wantErr: false,
		},
		{
			name: "invalid bearer token",
			buildAuthorize: func() *authorize {
				return &authorize{}
			},
			args: args{
				ss: &mockServerStream{
					ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "token")),
				},
				info: &grpc.StreamServerInfo{
					FullMethod: "/test.Service/StreamMethod",
				},
				handler: func(srv interface{}, ss grpc.ServerStream) error {
					return nil
				},
			},
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name: "authenticate fails",
			buildAuthorize: func() *authorize {
				m := &mockAuthenticationProvider{}
				m.On("Authenticate", mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
				return &authorize{authentication: m}
			},
			args: args{
				ss: &mockServerStream{
					ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid-token")),
				},
				info: &grpc.StreamServerInfo{
					FullMethod: "/test.Service/StreamMethod",
				},
				handler: func(srv interface{}, ss grpc.ServerStream) error {
					return nil
				},
			},
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name: "authorization succeeds",
			buildAuthorize: func() *authorize {
				m := &mockFieldValidator{}
				m.On("Execute", mock.Anything, mock.Anything).Return(nil).Once()
				m.On("AddToContext", mock.Anything).Return(context.Background()).Once()
				return &authorize{
					validators: []FieldValidator{m},
				}
			},
			args: args{
				ss: &mockServerStream{
					ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenWithClaimsString)),
				},
				info: &grpc.StreamServerInfo{
					FullMethod: "/test.Service/StreamMethod",
				},
				handler: func(srv interface{}, ss grpc.ServerStream) error {
					return nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorize := tt.buildAuthorize()
			interceptor := authorize.GRPCStreamInterceptor()
			err := interceptor(nil, tt.args.ss, tt.args.info, tt.args.handler)

			if tt.wantErr {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, tt.wantErrCode, st.Code())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_NewAllowedOriginWithoutAuthorize(t *testing.T) {
	type args struct {
		allowedSources []string
	}

	tests := map[string]struct {
		args args
		want *allowedOriginWithoutAuthorize
	}{
		"when instantiating a new allowed origin without authorize, should return a new instance": {
			args: args{
				allowedSources: []string{"localhost"},
			},
			want: &allowedOriginWithoutAuthorize{
				allowedSources: []string{"localhost"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := NewAllowedOriginWithoutAuthorize(tt.args.allowedSources)

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_NewAllowedOriginWithoutAuthorize_HTTPMiddleware(t *testing.T) {
	type args struct {
		next http.Handler
		req  *http.Request
	}

	tests := []struct {
		name                               string
		buildAllowedOriginWithoutAuthorize func() *allowedOriginWithoutAuthorize
		args                               args
		wantStatusCode                     int
		wantBody                           string
	}{
		{
			name: "use remote address and host from net package to check if the origin, should allow the request",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"example.com"},
				}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					return httptest.NewRequest(http.MethodGet, "/", nil)
				}(),
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "next handler",
		},
		{
			name: "use remote address and host from net package to check if the origin, should not allow the request",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"localhost"},
				}
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("next handler"))
				}),
				req: func() *http.Request {
					return httptest.NewRequest(http.MethodGet, "/", nil)
				}(),
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "next handler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the mock
			allowed := tt.buildAllowedOriginWithoutAuthorize()

			// Create the middleware
			middleware := allowed.HTTPMiddleware(tt.args.next)

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			middleware.ServeHTTP(rr, tt.args.req)

			// Check the status code
			assert.Equal(t, tt.wantStatusCode, rr.Code)

			// Check the response body
			assert.Equal(t, tt.wantBody, rr.Body.String())
		})
	}
}

func Test_NewAllowedOriginWithoutAuthorize_GRPCInterceptor(t *testing.T) {
	type args struct {
		ctx     context.Context
		req     interface{}
		info    *grpc.UnaryServerInfo
		handler grpc.UnaryHandler
	}

	tests := []struct {
		name                               string
		buildAllowedOriginWithoutAuthorize func() *allowedOriginWithoutAuthorize
		args                               args
		wantErr                            bool
	}{
		{
			name: "use remote address and host from net package to check if the origin should allow the request",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"example.com"},
				}
			},
			args: args{
				ctx: func() context.Context {
					ctx := context.Background()

					// Agregamos el peer con una dirección IP
					p := &peer.Peer{
						Addr: &net.TCPAddr{
							IP:   net.ParseIP("192.168.1.1"),
							Port: 50051,
						},
					}
					ctx = peer.NewContext(ctx, p)

					// Agregamos el metadata con `:authority`
					md := metadata.Pairs(":authority", "example.com")
					ctx = metadata.NewIncomingContext(ctx, md)

					return ctx
				}(),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr: false,
		},
		{
			name: "use remote address and host from net package to check if the origin should not allow the request",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"localhost"},
				}
			},
			args: args{
				ctx: func() context.Context {
					ctx := context.Background()

					// Agregamos el peer con una dirección IP
					p := &peer.Peer{
						Addr: &net.TCPAddr{
							IP:   net.ParseIP("192.168.1.1"),
							Port: 50051,
						},
					}
					ctx = peer.NewContext(ctx, p)

					// Agregamos el metadata con `:authority`
					md := metadata.Pairs(":authority", "example.com")
					ctx = metadata.NewIncomingContext(ctx, md)

					return ctx
				}(),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr: false,
		},
		{
			name: "use remote address and host from net package to check if the origin and not found `:authority` and `:path`",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"localhost"},
				}
			},
			args: args{
				ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
				req: nil,
				info: &grpc.UnaryServerInfo{
					FullMethod: "/test.Service/Method",
				},
				handler: func(ctx context.Context, req interface{}) (interface{}, error) {
					return "success", nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := tt.buildAllowedOriginWithoutAuthorize()
			interceptor := allowed.GRPCInterceptor()

			_, err := interceptor(tt.args.ctx, tt.args.req, tt.args.info, tt.args.handler)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_NewAllowedOriginWithoutAuthorize_GRPCStreamInterceptor(t *testing.T) {
	type args struct {
		ss      grpc.ServerStream
		info    *grpc.StreamServerInfo
		handler grpc.StreamHandler
	}

	tests := []struct {
		name                               string
		buildAllowedOriginWithoutAuthorize func() *allowedOriginWithoutAuthorize
		args                               args
		wantErr                            bool
	}{
		{
			name: "use remote address and host from net package to check if the origin should allow the request",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"example.com"},
				}
			},
			args: args{
				ss: &mockServerStream{
					ctx: func() context.Context {
						ctx := context.Background()

						// Agregamos el peer con una dirección IP
						p := &peer.Peer{
							Addr: &net.TCPAddr{
								IP:   net.ParseIP("192.168.1.1"),
								Port: 50051,
							},
						}
						ctx = peer.NewContext(ctx, p)

						// Agregamos el metadata con `:authority`
						md := metadata.Pairs(":authority", "example.com")
						ctx = metadata.NewIncomingContext(ctx, md)

						return ctx
					}(),
				},
				info: &grpc.StreamServerInfo{
					FullMethod: "/test.Service/StreamMethod",
				},
				handler: func(srv interface{}, ss grpc.ServerStream) error {
					return nil
				},
			},
			wantErr: false,
		},
		{
			name: "use remote address and host from net package to check if the origin should not allow the request",
			buildAllowedOriginWithoutAuthorize: func() *allowedOriginWithoutAuthorize {
				return &allowedOriginWithoutAuthorize{
					allowedSources: []string{"localhost"},
				}
			},
			args: args{
				ss: &mockServerStream{
					ctx: func() context.Context {
						ctx := context.Background()

						// Agregamos el peer con una dirección IP
						p := &peer.Peer{
							Addr: &net.TCPAddr{
								IP:   net.ParseIP("192.168.1.1"),
								Port: 50051,
							},
						}
						ctx = peer.NewContext(ctx, p)

						// Agregamos el metadata con `:authority`
						md := metadata.Pairs(":authority", "example.com")
						ctx = metadata.NewIncomingContext(ctx, md)

						return ctx
					}(),
				},
				info: &grpc.StreamServerInfo{
					FullMethod: "/test.Service/StreamMethod",
				},
				handler: func(srv interface{}, ss grpc.ServerStream) error {
					return nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := tt.buildAllowedOriginWithoutAuthorize()
			interceptor := allowed.GRPCStreamInterceptor()

			err := interceptor(nil, tt.args.ss, tt.args.info, tt.args.handler)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_newHTTPRequestAdapter(t *testing.T) {
	type args struct {
		r *http.Request
	}

	tests := map[string]struct {
		args args
		want RequestAdapter
	}{
		"when instantiating a new http request adapter, should return a new instance": {
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			want: &httpRequestAdapter{
				request: httptest.NewRequest(http.MethodGet, "/", nil),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := newHTTPRequestAdapter(tt.args.r)

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_httpRequestAdapter_Context(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		want   context.Context
	}{
		"should return the context": {
			fields: fields{
				request: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			want: context.Background(),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.Context())
		})
	}
}

func Test_httpRequestAdapter_GetPath(t *testing.T) {
	type testCase struct {
		routePattern string
		requestPath  string
	}

	tests := map[string]testCase{
		"should return the route pattern for /test/{id}": {
			routePattern: "/test/{id}",
			requestPath:  "/test/123",
		},
		"should return the route pattern for /users/{userID}/profile": {
			routePattern: "/users/{userID}/profile",
			requestPath:  "/users/42/profile",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := chi.NewRouter()

			r.Get(tt.routePattern, func(w http.ResponseWriter, req *http.Request) {
				adapter := newHTTPRequestAdapter(req)
				assert.Equal(t, tt.routePattern, adapter.GetPath())
			})

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			recorder := httptest.NewRecorder()

			r.ServeHTTP(recorder, req)
		})
	}
}

func Test_httpRequestAdapter_GetMethod(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		want   string
	}{
		"should return the method": {
			fields: fields{
				request: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			want: http.MethodGet,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.GetMethod())
		})
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("forced read error")
}

func Test_httpRequestAdapter_GetBody(t *testing.T) {
	tests := map[string]struct {
		requestBody io.Reader
		want        []byte
		wantErr     bool
	}{
		"should return the request body correctly": {
			requestBody: bytes.NewBufferString(`{"message": "hello"}`),
			want:        []byte(`{"message": "hello"}`),
			wantErr:     false,
		},
		"should return an empty body when request body is empty": {
			requestBody: bytes.NewBufferString(""),
			want:        []byte(""),
			wantErr:     false,
		},
		"should return an error when body read fails": {
			requestBody: &errorReader{},
			want:        nil,
			wantErr:     true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", io.NopCloser(tt.requestBody))

			adapter := newHTTPRequestAdapter(req)

			body, err := adapter.GetBody()

			assert.Equal(t, tt.want, body)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_httpRequestAdapter_GetURLParams(t *testing.T) {
	tests := map[string]struct {
		routePattern string
		requestPath  string
		got          map[string]string
	}{
		"should return the URL params for /test/{id}": {
			routePattern: "/test/{id}",
			requestPath:  "/test/123",
			got:          map[string]string{"id": "123"},
		},
		"should return the URL params for /users/{userID}/profile": {
			routePattern: "/users/{userID}/profile",
			requestPath:  "/users/42/profile",
			got:          map[string]string{"userID": "42"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := chi.NewRouter()

			r.Get(tt.routePattern, func(w http.ResponseWriter, req *http.Request) {
				adapter := newHTTPRequestAdapter(req)
				assert.Equal(t, tt.got, adapter.GetURLParams())
			})

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			recorder := httptest.NewRecorder()

			r.ServeHTTP(recorder, req)
		})
	}
}

func Test_httpRequestAdapter_GetQueryParams(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		want   map[string][]string
	}{
		"should return the query params": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/?key=value", nil)
					return req
				}(),
			},
			want: map[string][]string{"key": {"value"}},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.GetQueryParams())
		})
	}
}

func Test_httpRequestAdapter_GetHeader(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		key    string
		want   string
	}{
		"should return the header value": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("key", "value")
					return req
				}(),
			},
			key:  "key",
			want: "value",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.GetHeader(tt.key))
		})
	}
}

func Test_httpRequestAdapter_GetRemoteAddr(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		want   string
	}{
		"should return the remote address": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.RemoteAddr = ""
					return req
				}(),
			},
			want: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.GetRemoteAddr())
		})
	}
}

func Test_httpRequestAdapter_GetHost(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		want   string
	}{
		"should return the host": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Host = "localhost"
					return req
				}(),
			},
			want: "localhost",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.GetHost())
		})
	}
}

func Test_httpRequestAdapter_GetBearerToken(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields  fields
		want    string
		wantErr error
	}{
		"should return the bearer token": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization", "Bearer token")
					return req
				}(),
			},
			want:    "token",
			wantErr: nil,
		},
		"should return an empty string when the bearer token is not present": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					return req
				}(),
			},
			want:    "",
			wantErr: errors.New("missing or invalid authorization header"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			got, err := r.GetBearerToken()

			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func Test_httpRequestAdapter_ShouldSkipAuthorize(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
		want   bool
	}{
		"should skip atuhorize key is present": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					ctx := context.WithValue(req.Context(), skipAuthorizeKey, true)
					return req.WithContext(ctx)
				}(),
			},
			want: true,
		},
		"should not skip authorize key is not present": {
			fields: fields{
				request: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			want: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			assert.Equal(t, tt.want, r.ShouldSkipAuthorize())
		})
	}
}

func Test_httpRequestAdapter_RemoveAuthorization(t *testing.T) {
	type fields struct {
		request *http.Request
	}

	tests := map[string]struct {
		fields fields
	}{
		"should remove the authorization header": {
			fields: fields{
				request: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("Authorization", "Bearer token")
					return req
				}(),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &httpRequestAdapter{
				request: tt.fields.request,
			}

			r.RemoveAuthorization()

			assert.Empty(t, r.GetHeader("Authorization"))
		})
	}
}

func Test_newGRPCRequestAdapter(t *testing.T) {
	type args struct {
		ctx        context.Context
		fullMethod string
	}

	tests := map[string]struct {
		args args
		want RequestAdapter
	}{
		"when instantiating a new grpc request adapter, should return a new instance": {
			args: args{
				ctx:        context.Background(),
				fullMethod: "/test.Service/Method",
			},
			want: &grpcRequestAdapter{
				ctx:        context.Background(),
				fullMethod: "/test.Service/Method",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := newGRPCRequestAdapter(tt.args.ctx, tt.args.fullMethod)

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_grpcRequestAdapter_Context(t *testing.T) {
	type fields struct {
		ctx        context.Context
		fullMethod string
	}

	tests := map[string]struct {
		fields fields
		want   context.Context
	}{
		"should return the context": {
			fields: fields{
				ctx:        context.Background(),
				fullMethod: "/test.Service/Method",
			},
			want: context.Background(),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &grpcRequestAdapter{
				ctx:        tt.fields.ctx,
				fullMethod: tt.fields.fullMethod,
			}

			assert.Equal(t, tt.want, r.Context())
		})
	}
}

func Test_grpcRequestAdapter_GetPath(t *testing.T) {
	type fields struct {
		ctx        context.Context
		fullMethod string
	}

	tests := map[string]struct {
		fields fields
		want   string
	}{
		"should return the full method": {
			fields: fields{
				ctx:        context.Background(),
				fullMethod: "/test.Service/Method",
			},
			want: "/test.Service/Method",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &grpcRequestAdapter{
				ctx:        tt.fields.ctx,
				fullMethod: tt.fields.fullMethod,
			}

			assert.Equal(t, tt.want, r.GetPath())
		})
	}
}

func Test_grpcRequestAdapter_GetMethod(t *testing.T) {
	type fields struct {
		ctx        context.Context
		fullMethod string
	}

	tests := map[string]struct {
		fields fields
		want   string
	}{
		"should return the method": {
			fields: fields{
				ctx:        context.Background(),
				fullMethod: "/test.Service/Method",
			},
			want: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &grpcRequestAdapter{
				ctx:        tt.fields.ctx,
				fullMethod: tt.fields.fullMethod,
			}

			assert.Equal(t, tt.want, r.GetMethod())
		})
	}
}
