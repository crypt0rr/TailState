# syntax=docker/dockerfile:1.27.1
# Keep this compiler aligned with the `go` directive in go.mod. CI checks the
# two declarations so the tested and published binaries use the same toolchain.
# The builder runs on the build host's native platform and cross-compiles the
# pure-Go binary for each target, so multi-architecture builds do not compile
# under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /source
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOARM="${TARGETVARIANT#v}" CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/tailstate ./cmd/tailstate

# CA certificates and the empty /data directory are architecture-independent,
# so this stage also runs natively on the build platform.
FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime-files
RUN mkdir -p /data \
    && chown 10001:10001 /data

FROM scratch
ARG VERSION=dev
ARG GO_VERSION=1.27.1
ARG BUILD_COMMIT=unknown
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
# The runtime base is scratch, so no base-image labels are set. The exact builder image digest is recorded in the BuildKit
# provenance attestation; GO_VERSION is checked against go.mod and the FROM
# line by scripts/check-go-toolchain.sh.
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${BUILD_COMMIT}" \
      org.opencontainers.image.source="https://github.com/crypt0rr/tailstate" \
      org.opencontainers.image.build.go="${GO_VERSION}" \
      org.opencontainers.image.build.target.os="${TARGETOS}" \
      org.opencontainers.image.build.target.architecture="${TARGETARCH}" \
      org.opencontainers.image.build.target.variant="${TARGETVARIANT}"
COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files --chown=10001:10001 /data /data
COPY --from=builder /out/tailstate /tailstate
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
# Containers receive their network boundary from Compose/Docker port
# publishing; keep the application reachable on the container bridge while
# standalone binaries default to loopback in boot.Config.
ENV TAILSTATE_LISTEN_ADDR=0.0.0.0:8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/tailstate", "healthcheck"]
ENTRYPOINT ["/tailstate"]
CMD ["serve"]
