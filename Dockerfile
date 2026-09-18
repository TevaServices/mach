# syntax=docker/dockerfile:1
# Multi-stage build: no Go toolchain needed on the host.
#
# The mach-server image is the control plane (the only public component).
# It also carries prebuilt `mach` remote-connection binaries for all
# supported OS/arch targets under /opt/mach-agents/, so target machines
# never need a Go toolchain: docker cp them out and copy over.
#
# The toolchain is pinned to the go directive in go.mod. Keep them in step:
# the release attestation records which toolchain built each binary, and a
# mismatch here is exactly the kind of drift the attestation exists to expose.
#
# .git is deliberately not excluded via .dockerignore: Go stamps the VCS
# revision into each binary, `mach-server attest` reads it back out, and that
# is what lets a shipped agent binary be traced to a commit. Build from a
# clean checkout — a dirty tree is recorded as vcs.modified, and
# `push-update --attestation` refuses to ship such a build.
#
# --platform=$BUILDPLATFORM pins this stage to the machine running the build,
# with TARGETOS/TARGETARCH naming the image being built. In a multi-platform
# build that is the difference between minutes and tens of minutes: the
# alternative (letting the stage take the target platform) compiles Go inside
# a QEMU-emulated arm64 toolchain, while Go itself cross-compiles natively in
# the time it takes to compile the host arch.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
# The image being built, supplied by buildx per platform. Nothing sets these
# in a plain `docker build` — then they are empty, and building the empty
# GOOS/GOARCH pair is the host's own, so a single-platform build behaves
# exactly as before.
ARG TARGETOS
ARG TARGETARCH
# go.sum too, so the layer is verified against the committed hashes rather than
# letting `go mod download` write a fresh go.sum for whatever the proxy served.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The release workflow passes the tag in (v0.3.0 becomes 0.3.0). A plain
# `docker build` leaves this empty, and empty has to mean "no override" rather
# than an empty version — hence the guard below, which never emits -X without a
# value. The version literal itself lives in exactly one file
# (internal/version/version.go) and is deliberately not repeated here.
ARG MACH_VERSION=
RUN <<EOF
set -e
export CGO_ENABLED=0
export GOOS="$TARGETOS" GOARCH="$TARGETARCH"
LDFLAGS="-s -w"
if [ -n "$MACH_VERSION" ]; then
  LDFLAGS="$LDFLAGS -X github.com/TevaServices/mach/internal/version.Version=$MACH_VERSION"
fi
go build -trimpath -ldflags "$LDFLAGS" -o /out/mach-server ./cmd/mach-server
mkdir -p /out/agents
GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/mach-darwin-amd64       ./cmd/mach
GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/mach-darwin-arm64      ./cmd/mach
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/mach-linux-amd64       ./cmd/mach
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/mach-linux-arm64       ./cmd/mach
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/mach-windows-amd64.exe ./cmd/mach
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/mach-windows-arm64.exe ./cmd/mach
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

# Attestations are made after the image is running, not during the build:
# they are signed with the control plane's identity key, which is generated on
# first `serve` and lives in /data. Signing with a key that only exists at
# runtime is what ties an attestation to the control plane that will actually
# push the update.
#
#   docker compose exec mach-server mach-server attest /opt/mach-agents/mach-linux-amd64 0.2.0
#   docker compose cp mach-server:/opt/mach-agents/mach-linux-amd64.intoto.jsonl .
#   docker compose exec mach-server mach-server verify-attestation \
#       /opt/mach-agents/mach-linux-amd64.intoto.jsonl /opt/mach-agents/mach-linux-amd64
#   docker compose exec mach-server mach-server push-update \
#       <machine> /opt/mach-agents/mach-linux-amd64 0.2.0 \
#       --attestation /opt/mach-agents/mach-linux-amd64.intoto.jsonl
