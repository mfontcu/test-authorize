package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func Test_MultiplexorInterceptor(t *testing.T) {
	mockInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return "intercepted", nil
	}

	defaultHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "default", nil
	}

	tests := []struct {
		name         string
		interceptors map[string]grpc.UnaryServerInterceptor
		method       string
		want         string
	}{
		{
			name:         "Interceptor found",
			interceptors: map[string]grpc.UnaryServerInterceptor{"/test.Method": mockInterceptor},
			method:       "/test.Method",
			want:         "intercepted",
		},
		{
			name:         "No interceptor found",
			interceptors: map[string]grpc.UnaryServerInterceptor{},
			method:       "/test.Method",
			want:         "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := MultiplexorInterceptor(tt.interceptors)
			info := &grpc.UnaryServerInfo{FullMethod: tt.method}
			resp, _ := interceptor(context.Background(), nil, info, defaultHandler)

			assert.Equal(t, tt.want, resp)
		})
	}
}

func Test_MultiplexorStreamInterceptor(t *testing.T) {
	mockStreamInterceptor := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return nil
	}

	defaultStreamHandler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	tests := []struct {
		name         string
		interceptors map[string]grpc.StreamServerInterceptor
		method       string
		wantErr      error
	}{
		{
			name:         "Stream interceptor found",
			interceptors: map[string]grpc.StreamServerInterceptor{"/test.StreamMethod": mockStreamInterceptor},
			method:       "/test.StreamMethod",
			wantErr:      nil,
		},
		{
			name:         "No stream interceptor found",
			interceptors: map[string]grpc.StreamServerInterceptor{},
			method:       "/test.StreamMethod",
			wantErr:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := MultiplexorStreamInterceptor(tt.interceptors)
			info := &grpc.StreamServerInfo{FullMethod: tt.method}
			err := interceptor(nil, nil, info, defaultStreamHandler)

			assert.NoError(t, err)
		})
	}
}

func Test_ChainUnaryInterceptors(t *testing.T) {
	first := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}

	second := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return "chained", nil
	}

	chained := ChainUnaryInterceptors(first, second)

	resp, _ := chained(context.Background(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "original", nil
	})

	assert.Equal(t, "chained", resp)
}

func Test_ChainStreamInterceptors(t *testing.T) {
	first := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}

	second := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return nil
	}

	chained := ChainStreamInterceptors(first, second)

	err := chained(nil, nil, &grpc.StreamServerInfo{}, func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	})

	assert.NoError(t, err)
}
