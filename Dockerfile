# syntax=docker/dockerfile:experimental

FROM rust:1.51 as builder

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

# read features argument. Use "default" because [ -z "$features" ] doesn't work
ARG features="default"
RUN echo "installing with features: ["$features"]"

# install tofnd
# use --locked for CI builds: https://doc.rust-lang.org/cargo/commands/cargo-install.html#manifest-options
RUN --mount=type=ssh if [ "$features" = "default" ]; then \
  cargo install --locked --path .; \
  else \
  cargo install --locked --features ${features} --path .; \
  fi

FROM debian:buster-slim as runner

COPY --from=builder /tofnd/target/release/tofnd /usr/local/bin

COPY ./entrypoint.sh /

VOLUME [ "/.tofnd" ]

ENV UNSAFE ""
ENV MNEMONIC_CMD ""
ENTRYPOINT ["/entrypoint.sh"]
