# syntax=docker/dockerfile:experimental

FROM rust:1.49 as builder

RUN set -ex \
  && apt-get update \
  && apt-get install -qq --no-install-recommends ca-certificates openssh-client git make

WORKDIR /tofnd

COPY ./Cargo.toml .
COPY ./Cargo.lock .
# COPY ./.cargo ./.cargo

# RUN git config --global url."git@github.com:axelarnetwork".insteadOf https://github.com/axelarnetwork
RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts

# build dependencies separately
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN --mount=type=ssh cargo build --release

COPY src ./src
COPY proto ./proto
COPY build.rs ./build.rs

RUN rustup component add rustfmt

# build tofnd
RUN cargo build --release
RUN --mount=type=ssh cargo install --path .

FROM debian:buster-slim as runner

COPY --from=builder /tofnd/target/release/tofnd /

COPY ./entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/tofnd"]
