# syntax=docker/dockerfile:1.26.0
FROM golang:1.26.6-alpine3.24@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
ARG VERSION=dev
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
COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files --chown=10001:10001 /data /data
COPY --from=builder /out/tailstate /tailstate
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/tailstate", "healthcheck"]
ENTRYPOINT ["/tailstate"]
CMD ["serve"]
