FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home cedar
COPY --from=builder /build/target/release/cedar-sidecar /usr/local/bin/cedar-sidecar
USER cedar
EXPOSE 8180
HEALTHCHECK --interval=5s --timeout=2s --retries=10 CMD curl -sf http://localhost:8180/health || exit 1
CMD ["cedar-sidecar"]
