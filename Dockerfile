FROM rust:1.49 as builder
WORKDIR /tofnd
COPY ./Cargo.toml .
COPY ./Cargo.lock .

# build dependencies separately
RUN git config --global url."git@github.com:axelarnetwork".insteadOf https://github.com/axelarnetwork
RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
RUN mkdir src && echo 'fn main() {}' > src/main.rs 
RUN --mount=type=ssh cargo build --release

# build tofnd
COPY src ./src
RUN cargo build --release
RUN cargo install --path .

# FROM debian:buster-slim as runner
# RUN apt-get update && apt-get install -y openssl ca-certificates redis
# COPY --from=builder /blockchain-state-buffer/target/release/blockchain-state-buffer /
# ENV RUST_LOG=info
# ENV JSON_RPC_URL=ws://35.203.107.66/7dceb455-0f89-574f-8792-0dd83c2586d3/eth/parity/0/stream
# ENV REDIS_URL=redis://127.0.0.1:6379
# COPY ./entrypoint.sh /
# COPY ./check-liveness.sh /
# ENTRYPOINT ["/entrypoint.sh"]
# CMD ["/blockchain-state-buffer"]