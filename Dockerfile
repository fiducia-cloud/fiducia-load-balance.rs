# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-load-balance. Clones sibling path
# dependencies so Cargo resolves the same layout as local development.
FROM rust:1.97.0-slim-bookworm@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG ROUTING_REF=543b4ea3b3bba28b66c15a97a27514488d2ccce3
ARG INTERFACES_REF=487e470c45ab5851e8f6f3b1dc048fe067fbf408
RUN git init fiducia-routing.rs \
    && git -C fiducia-routing.rs remote add origin https://github.com/fiducia-cloud/fiducia-routing.rs.git \
    && git -C fiducia-routing.rs fetch --depth 1 origin "$ROUTING_REF" \
    && test "$(git -C fiducia-routing.rs rev-parse FETCH_HEAD)" = "$ROUTING_REF" \
    && git -C fiducia-routing.rs checkout --detach FETCH_HEAD \
    && test "$(git -C fiducia-routing.rs rev-parse HEAD)" = "$ROUTING_REF"
RUN git init fiducia-interfaces \
    && git -C fiducia-interfaces remote add origin https://github.com/fiducia-cloud/fiducia-interfaces.git \
    && git -C fiducia-interfaces fetch --depth 1 origin "$INTERFACES_REF" \
    && test "$(git -C fiducia-interfaces rev-parse FETCH_HEAD)" = "$INTERFACES_REF" \
    && git -C fiducia-interfaces checkout --detach FETCH_HEAD \
    && test "$(git -C fiducia-interfaces rev-parse HEAD)" = "$INTERFACES_REF"
COPY . fiducia-load-balance.rs
WORKDIR /build/fiducia-load-balance.rs
RUN cargo build --locked --release && strip target/release/fiducia-load-balance

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:66aa873a4a14fb164aa01296058efd8253744606d72715e45acface073359faa
COPY --from=build --chown=65532:65532 /build/fiducia-load-balance.rs/target/release/fiducia-load-balance /usr/local/bin/fiducia-load-balance
EXPOSE 8088
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-load-balance"]
