# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-load-balance. Clones the pinned fiducia-routing
# crate as a sibling so the path dependency resolves.
FROM rust:1-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG ROUTING_REF=v0.1.0
RUN git clone --depth 1 --branch "$ROUTING_REF" \
    https://github.com/fiducia-cloud/fiducia-routing.rs.git fiducia-routing.rs
COPY . fiducia-load-balance.rs
WORKDIR /build/fiducia-load-balance.rs
RUN cargo build --release && strip target/release/fiducia-load-balance

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/fiducia-load-balance.rs/target/release/fiducia-load-balance /usr/local/bin/fiducia-load-balance
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/fiducia-load-balance"]
