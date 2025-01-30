package interceptor

import (
	"context"

	"google.golang.org/grpc"
)

// MultiplexorInterceptor assigns a specific unary interceptor based on the method.
func MultiplexorInterceptor(interceptors map[string]grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Search for a specific interceptor for the method
		if interceptor, exists := interceptors[info.FullMethod]; exists {
			return interceptor(ctx, req, info, handler)
		}

		// If there is no specific interceptor, execute the handler
		return handler(ctx, req)
	}
}

// MultiplexorStreamInterceptor selects a specific stream interceptor based on the method.
func MultiplexorStreamInterceptor(interceptors map[string]grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Search for a specific interceptor for the method
		if interceptor, exists := interceptors[info.FullMethod]; exists {
			return interceptor(srv, ss, info, handler)
		}

		// Execute the handler if there is no specific interceptor
		return handler(srv, ss)
	}
}

// ChainUnaryInterceptors conbines multiple unary interceptors into one.
func ChainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Compose interceptors in reverse order
		currentHandler := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := currentHandler
			currentHandler = func(currentCtx context.Context, currentReq interface{}) (interface{}, error) {
				return interceptor(currentCtx, currentReq, info, next)
			}
		}

		// Execute the chain
		return currentHandler(ctx, req)
	}
}

// ChainStreamInterceptors combines multiple stream interceptors into one.
func ChainStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Compose interceptors in reverse order
		currentHandler := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := currentHandler
			currentHandler = func(currentSrv interface{}, currentStream grpc.ServerStream) error {
				return interceptor(currentSrv, currentStream, info, next)
			}
		}

		// Execute the chain
		return currentHandler(srv, ss)
	}
}
