FROM rust:1.85-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/deltadrop-common crates/deltadrop-common
COPY crates/deltadrop-relay crates/deltadrop-relay

RUN sed -i '/deltadrop-client/d;/lumenic/d' Cargo.toml \
    && CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --target x86_64-unknown-linux-musl -p deltadrop-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/deltadrop-relay /usr/local/bin/deltadrop-relay

ENV DELTADROP_BIND=0.0.0.0:8787
ENV DELTADROP_DATA_DIR=/var/lib/deltadrop
ENV MAX_CACHE_GB=50
ENV CHUNK_TTL_HOURS=72
ENV RUST_LOG=deltadrop_relay=info

VOLUME ["/var/lib/deltadrop"]
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/deltadrop-relay"]
