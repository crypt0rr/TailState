# syntax=docker/dockerfile:1.24.0
FROM rust:1.97-alpine AS builder
RUN apk add --no-cache build-base musl-dev
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM alpine:3.24
RUN apk add --no-cache ca-certificates wget \
    && addgroup -S -g 10001 tailstate \
    && adduser -S -D -H -u 10001 -G tailstate tailstate \
    && mkdir -p /config /data \
    && chown tailstate:tailstate /data
COPY --from=builder /source/target/release/tailstate /usr/local/bin/tailstate
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/tailstate"]
CMD ["run", "--config", "/config/tailstate.yaml"]
