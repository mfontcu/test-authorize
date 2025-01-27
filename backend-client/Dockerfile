ARG IMAGE_VERSION
FROM golang:${IMAGE_VERSION:-1.23.4} AS build

WORKDIR /app

COPY . .

ARG GITHUB_USER
ARG GITHUB_TOKEN

ENV GO111MODULE=on
ENV CGO_ENABLED=0

RUN GOOS=linux GOARCH=amd64 go build -o /go/bin/app .

FROM alpine AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/app ./

ENTRYPOINT ["./app"]