# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-load-balance. Clones sibling path
# dependencies so Cargo resolves the same layout as local development.
FROM rust:1-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG ROUTING_REF=main
ARG INTERFACES_REF=main
RUN git clone --depth 1 --branch "$ROUTING_REF" \
    https://github.com/fiducia-cloud/fiducia-routing.rs.git fiducia-routing.rs
RUN git clone --depth 1 --branch "$INTERFACES_REF" \
    https://github.com/fiducia-cloud/fiducia-interfaces.git fiducia-interfaces
COPY . fiducia-load-balance.rs
WORKDIR /build/fiducia-load-balance.rs
RUN cargo build --release && strip target/release/fiducia-load-balance

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build --chown=65532:65532 /build/fiducia-load-balance.rs/target/release/fiducia-load-balance /usr/local/bin/fiducia-load-balance
EXPOSE 8088
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-load-balance"]
