# syntax=docker/dockerfile:experimental

FROM rust:1.49 as builder

RUN set -ex \
    && apt-get update \
    && apt-get install -qq --no-install-recommends ca-certificates openssh-client git make

WORKDIR /tofnd

COPY ./Cargo.toml .
COPY ./Cargo.lock .

# pacify ssh: add github.com to known_hosts
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

# use --locked for CI builds: https://doc.rust-lang.org/cargo/commands/cargo-install.html#manifest-options
RUN --mount=type=ssh cargo install --locked --path .

FROM debian:buster-slim as runner

COPY --from=builder /tofnd/target/release/tofnd /usr/local/bin

COPY ./entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
# CMD ["/tofnd"]
