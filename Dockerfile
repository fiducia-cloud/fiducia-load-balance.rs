# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-load-balance. Clones sibling path
# dependencies so Cargo resolves the same layout as local development.
FROM rust:1.97.1-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG ROUTING_REF=543b4ea3b3bba28b66c15a97a27514488d2ccce3
ARG INTERFACES_REF=6e20a3f4df2e52b99a0ad6add83d4528262b5dbc
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build --chown=65532:65532 /build/fiducia-load-balance.rs/target/release/fiducia-load-balance /usr/local/bin/fiducia-load-balance
EXPOSE 8088
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-load-balance"]
