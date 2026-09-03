# syntax=docker/dockerfile:1.27.0
# Keep this compiler aligned with the `go` directive in go.mod. CI checks the
# two declarations so the tested and published binaries use the same toolchain.
FROM golang:1.27.1-alpine3.24@sha256:3f6d04dc61331ee3c2fbbaad62d54412a84680f6a041d269a20a5270a078515b AS builder
ARG VERSION=dev
ARG GO_VERSION=1.27.1
ARG BUILD_COMMIT=unknown
WORKDIR /source
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/tailstate ./cmd/tailstate

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime-files
RUN mkdir -p /data \
    && chown 10001:10001 /data

FROM scratch
ARG VERSION=dev
ARG GO_VERSION=1.27.1
ARG BUILD_COMMIT=unknown
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${BUILD_COMMIT}" \
      org.opencontainers.image.source="https://github.com/crypt0rr/tailstate" \
      org.opencontainers.image.build.go="${GO_VERSION}" \
      org.opencontainers.image.base.name="golang:1.27.1-alpine3.24" \
      org.opencontainers.image.base.digest="sha256:3f6d04dc61331ee3c2fbbaad62d54412a84680f6a041d269a20a5270a078515b" \
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
