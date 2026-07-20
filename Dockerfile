# syntax=docker/dockerfile:1.24.0
FROM golang:1.26.5-alpine3.24 AS builder
ARG VERSION=dev
WORKDIR /source
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/tailstate ./cmd/tailstate

FROM alpine:3.24 AS runtime-files
RUN mkdir -p /data \
    && chown 10001:10001 /data

FROM scratch
COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files --chown=10001:10001 /data /data
COPY --from=builder /out/tailstate /tailstate
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/tailstate", "healthcheck"]
ENTRYPOINT ["/tailstate"]
CMD ["serve"]
