# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-load-balance. Clones sibling path
# dependencies so Cargo resolves the same layout as local development.
FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG ROUTING_REF=c694bc5c58587bec12989a347e926c0040aacada
ARG INTERFACES_REF=ee8fe09f846f5a776d156c0b0d0d15582c8bd539
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build --chown=65532:65532 /build/fiducia-load-balance.rs/target/release/fiducia-load-balance /usr/local/bin/fiducia-load-balance
EXPOSE 8088
USER 65532:65532
# --- sops: this final stage has no shell (distroless/scratch), so runtime
# decryption cannot run inside the container. Inject secrets HOST-SIDE at
# `docker run` instead — never at build, never as --build-arg:
#     just env-docker-run prod <image>        # decrypts env/enc/prod.env.enc
#                                             # and passes --env-file, no plaintext on disk
# or render a platform secret from the same ciphertext. See env/README.md.
ENTRYPOINT ["/usr/local/bin/fiducia-load-balance"]
