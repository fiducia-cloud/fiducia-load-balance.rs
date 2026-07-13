# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-load-balance. Clones sibling path
# dependencies so Cargo resolves the same layout as local development.
FROM rust:1.97.0-slim-bookworm@sha256:cfbb0e0ef7a73e736386bfa346f1cb0503c6d162969dc9426fb37834f3f64c25 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG ROUTING_REF=f0c86c2736b61cf3af7fa298a092fa435069cd64
ARG INTERFACES_REF=bbd8b52ce729ec34b0a9bff4dda6d0a448181797
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:ce0d66bc0f64aae46e6a03add867b07f42cc7b8799c949c2e898057b7f75a151
COPY --from=build --chown=65532:65532 /build/fiducia-load-balance.rs/target/release/fiducia-load-balance /usr/local/bin/fiducia-load-balance
EXPOSE 8088
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-load-balance"]
