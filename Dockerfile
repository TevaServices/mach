# syntax=docker/dockerfile:1
# Multi-stage build: no Go toolchain needed on the host.
#
# The mach-server image is the control plane (the only public component).
# It also carries prebuilt `mach` remote-connection binaries for all
# supported OS/arch targets under /opt/mach-agents/, so target machines
# never need a Go toolchain: docker cp them out and copy over.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN <<EOF
set -e
export CGO_ENABLED=0
go build -trimpath -ldflags="-s -w" -o /out/mach-server ./cmd/mach-server
mkdir -p /out/agents
GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/agents/mach-darwin-amd64       ./cmd/mach
GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /out/agents/mach-darwin-arm64      ./cmd/mach
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/agents/mach-linux-amd64       ./cmd/mach
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /out/agents/mach-linux-arm64       ./cmd/mach
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/agents/mach-windows-amd64.exe ./cmd/mach
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /out/agents/mach-windows-arm64.exe ./cmd/mach
EOF

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -u 6200 mach
COPY --from=build /out/mach-server /usr/local/bin/mach-server
COPY --from=build /out/agents/ /opt/mach-agents/
VOLUME /data
ENV MACH_DB=/data/mach.db
USER mach
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mach-server"]
CMD ["serve"]