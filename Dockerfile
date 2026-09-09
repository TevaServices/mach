# syntax=docker/dockerfile:1
# Multi-stage build: no Go toolchain needed on the host.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN <<EOF
set -e
export CGO_ENABLED=0
go build -trimpath -ldflags="-s -w" -o /out/machd ./cmd/machd
go build -trimpath -ldflags="-s -w" -o /out/mach ./cmd/mach
go build -trimpath -ldflags="-s -w" -o /out/machctl ./cmd/machctl
EOF

# Control plane image.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -u 6200 mach
COPY --from=build /out/machd /out/mach /out/machctl /usr/local/bin/
VOLUME /data
ENV MACH_DB=/data/mach.db
USER mach
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/machctl"]
CMD []