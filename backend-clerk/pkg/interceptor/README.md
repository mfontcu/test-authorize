# `multiplexor` & `chain` functions

## Introduction

This document describes the functionality of the `multiplexor` and `chain` functions, explaining their purpose and usage in a gRPC environment. Additionally, it details how these functions are compatible with each other and how they can be combined to enhance the management of interceptors in gRPC servers.

---

## `multiplexor` functions

The `multiplexor` functions provides gRPC interceptors that allow dynamically selecting a specific interceptor based on the invoked gRPC method. This is useful when different interception logic needs to be applied depending on the requested operation.

### What is it used for?

`multiplexor` is used when different interceptors need to be handled for different methods of a gRPC service. Instead of applying a single interceptor globally, rules can be defined so that each method has its own interceptor.

### Usage Example in `main.go`

In a gRPC configuration, a set of interceptors can be defined and assigned to specific methods for unary and streaming calls:

```go
interceptorsUnary := map[string]grpc.UnaryServerInterceptor{
	"/service.MethodA": authInterceptor,
	"/service.MethodB": loggingInterceptor,
}

interceptorsStream := map[string]grpc.StreamServerInterceptor{
	"/service.StreamMethodA": streamAuthInterceptor,
	"/service.StreamMethodB": streamLoggingInterceptor,
}

grpcServer := grpc.NewServer(
	grpc.UnaryInterceptor(interceptor.MultiplexorInterceptor(interceptorsUnary)),
	grpc.StreamInterceptor(interceptor.MultiplexorStreamInterceptor(interceptorsStream)),
)
```

In this case:
- `MethodA` will use `authInterceptor`, while `MethodB` will use `loggingInterceptor` for unary calls.
- `StreamMethodA` will use `streamAuthInterceptor`, while `StreamMethodB` will use `streamLoggingInterceptor` for streaming calls.

---

## `chain` functions

The `chain` functions are extension of the `multiplexor` functions, as `gRPC` natively provides chaining functions for interceptors (`grpc.ChainUnaryInterceptor` and` grpc.ChainStreamInterceptor`).

This functions are specifically designed to enable the chaining execution of interceptors within each service managed by `multiplexor`. That is, it allows the interceptors defined for each method in `multiplexor` to combine multiple interceptors into a single execution.

### What is it used for?

`chain` is used when multiple interceptors need to be defined per service method within `multiplexor`. Instead of defining a single interceptor per method, `chain` allows each method to have a sequence of interceptors executed in order.

### Usage Example in `main.go`

To apply multiple interceptors in a chain within `multiplexor`, the following can be done:

```go
interceptorsUnary := map[string]grpc.UnaryServerInterceptor{
	"/service.MethodA": interceptor.ChainUnaryInterceptors(loggingInterceptor, authInterceptor),
	"/service.MethodB": interceptor.ChainUnaryInterceptors(metricsInterceptor, tracingInterceptor),
}

interceptorsStream := map[string]grpc.StreamServerInterceptor{
	"/service.StreamMethodA": interceptor.ChainStreamInterceptors(streamLoggingInterceptor, streamAuthInterceptor),
	"/service.StreamMethodB": interceptor.ChainStreamInterceptors(streamMetricsInterceptor, streamTracingInterceptor),
}

grpcServer := grpc.NewServer(
	grpc.UnaryInterceptor(interceptor.MultiplexorInterceptor(interceptorsUnary)),
	grpc.StreamInterceptor(interceptor.MultiplexorStreamInterceptor(interceptorsStream)),
)
```

In this case:
- `MethodA` will execute `loggingInterceptor` followed by `authInterceptor`.
- `MethodB` will execute `metricsInterceptor` followed by `tracingInterceptor`.
- `StreamMethodA` will execute `streamLoggingInterceptor` followed by `streamAuthInterceptor`.
- `StreamMethodB` will execute `streamMetricsInterceptor` followed by `streamTracingInterceptor`.

This allows for a specific combination of interceptors per method while enabling multiple interceptors to be chained for each one.

---

## Compatibility Between `multiplexor` and `chain`

The `chain` function extends `multiplexor` by allowing multiple interceptors to be chained within each service managed by `multiplexor`.
- `multiplexor` enables assigning specific interceptors to particular methods.
- `chain` allows multiple interceptors to be combined for each method within `multiplexor`.

When combined, they provide a flexible solution that allows for precise assignment of interceptors to methods while enabling chaining when necessary.