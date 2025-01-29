package interceptor

import (
	"context"

	"google.golang.org/grpc"
)

// multiplexorHelper select a specific unary interceptor based on the method.
func multiplexorHelper[T any](
	interceptors map[string]T,
	method string,
	defaultHandler func() (interface{}, error),
	call func(T) (interface{}, error),
) (interface{}, error) {
	if interceptor, exists := interceptors[method]; exists {
		return call(interceptor)
	}
	return defaultHandler()
}

// MultiplexorInterceptor asigne a specific unary interceptor based on the method.
func MultiplexorInterceptor(interceptors map[string]grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		defaultHandler := func() (interface{}, error) {
			return handler(ctx, req)
		}

		callInterceptor := func(interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
			return interceptor(ctx, req, info, handler)
		}

		return multiplexorHelper(interceptors, info.FullMethod, defaultHandler, callInterceptor)
	}
}

// MultiplexorStreamInterceptor asign a specific streaming interceptor based on the method.
func MultiplexorStreamInterceptor(interceptors map[string]grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		defaultHandler := func() (interface{}, error) {
			return nil, handler(srv, ss)
		}

		callInterceptor := func(interceptor grpc.StreamServerInterceptor) (interface{}, error) {
			return nil, interceptor(srv, ss, info, handler)
		}

		_, err := multiplexorHelper(interceptors, info.FullMethod, defaultHandler, callInterceptor)
		return err
	}
}

// chainInterceptorsHelper combine multiple interceptors into one.
func chainInterceptorsHelper[T any](
	interceptors []T,
	call func(T, func() (interface{}, error)) (interface{}, error),
	defaultHandler func() (interface{}, error),
) (interface{}, error) {
	handler := defaultHandler
	for i := len(interceptors) - 1; i >= 0; i-- {
		next := handler
		interceptor := interceptors[i]
		handler = func() (interface{}, error) {
			return call(interceptor, next)
		}
	}
	return handler()
}

// ChainUnaryInterceptors combine multiple unary interceptors into one.
func ChainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		defaultHandler := func() (interface{}, error) {
			return handler(ctx, req)
		}

		callInterceptor := func(interceptor grpc.UnaryServerInterceptor, next func() (interface{}, error)) (interface{}, error) {
			return interceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
				return next()
			})
		}

		return chainInterceptorsHelper(interceptors, callInterceptor, defaultHandler)
	}
}

// ChainStreamInterceptors combine multiple streaming interceptors into one.
func ChainStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		defaultHandler := func() (interface{}, error) {
			return nil, handler(srv, ss)
		}

		callInterceptor := func(interceptor grpc.StreamServerInterceptor, next func() (interface{}, error)) (interface{}, error) {
			return nil, interceptor(srv, ss, info, func(srv interface{}, ss grpc.ServerStream) error {
				_, err := next()
				return err
			})
		}

		_, err := chainInterceptorsHelper(interceptors, callInterceptor, defaultHandler)
		return err
	}
}
