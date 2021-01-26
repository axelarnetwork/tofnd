# tofnd -- A threshold signature scheme daemon

A gRPC server wrapper for the [tofn](https://github.com/axelarnetwork/tofn) library.

## Status

Under active development.

## Setup

`tofnd` uses the [hyperium/tonic](https://github.com/hyperium/tonic) Rust gRPC implementation, which requires:
* Rust `1.39` or greater for the `async_await` feature
    ```
    $ rustup update
    ```
* `rustfmt` to tidy up the code it generates
    ```
    $ rustup component add rustfmt
    ```

## Run the server

```
$ cargo run
```
or specify listen port:
```
$ cargo run -- 50051
```
Terminate the server with `ctrl+C`.

The gRPC service is called `GG20`.

## Run the tests

```
$ cargo test
```
View terminal output for the `start_servers` test:
```
$ cargo test --package tofnd --bin tofnd -- tests::start_servers --exact --nocapture
```

## [FIX ME] Talk to the server using grpcurl

Install [grpcurl](https://github.com/fullstorydev/grpcurl) if you haven't already.

While `tofnd` is running, in a separate terminal:
```
$ grpcurl -plaintext -import-path ./proto -proto tofnd.proto -d '{"name": "Rick and Morty"}' [::]:50051 tofnd.GG20/SayHello
```