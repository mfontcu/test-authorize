module github.com/mfontcu/backend-clerk

go 1.23.4

require (
	github.com/go-chi/chi/v5 v5.2.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/mfontcu/test-authorize/backend-admin v0.0.0-00010101000000-000000000000
	github.com/mfontcu/test-authorize/backend-client v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.35.2
)

require (
	golang.org/x/net v0.32.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)

replace github.com/mfontcu/test-authorize/backend-admin => ../backend-admin

replace github.com/mfontcu/test-authorize/backend-client => ../backend-client
