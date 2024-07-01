FROM --platform=$BUILDPLATFORM rust:1.72.0-bookworm as build
WORKDIR /near
ARG TARGETARCH

COPY rust-toolchain.toml ./rust-toolchain.toml
RUN rustup show 
RUN apt-get update && apt-get install -y \
    git \
    jq \
    make \
    bash \
    openssl \
    libssl-dev \
    protobuf-compiler \
    pkg-config \
    cbindgen

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && echo "fn main() {}" > src/bin/dummy.rs
RUN cargo build --release --config net.git-fetch-with-cli=true --bin dummy

COPY ./ ./
RUN cargo build --release --config net.git-fetch-with-cli=true
RUN ldd target/release/near-offchain-lightclient 
RUN cp target/release/near-offchain-lightclient /near/near-offchain-light-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssl libssl-dev pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /near/near-offchain-light-client /usr/local/bin
COPY --from=build /near/default.toml /var/light-client.toml

RUN ldd /usr/local/bin/near-offchain-light-client
ENTRYPOINT ["/usr/local/bin/near-offchain-light-client"]
