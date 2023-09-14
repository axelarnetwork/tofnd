# syntax=docker/dockerfile:experimental

FROM rust:latest as builder

RUN set -ex \
  && apt-get update \
  && apt-get install -qq --no-install-recommends ca-certificates openssh-client git make

WORKDIR /tofnd

COPY ./Cargo.toml .
COPY ./Cargo.lock .

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

FROM debian:stable-slim as runner
RUN addgroup --system --gid 1001 axelard && adduser --system --uid 1000 --ingroup axelard axelard
RUN mkdir /.tofnd && chown axelard /.tofnd
USER axelard
COPY --from=builder /tofnd/target/release/tofnd /usr/local/bin

COPY ./entrypoint.sh /

VOLUME [ "/.tofnd" ]

ENV UNSAFE ""
ENV MNEMONIC_CMD ""
ENV NOPASSWORD ""
ENV TOFND_HOME ""
ENTRYPOINT ["/entrypoint.sh"]
