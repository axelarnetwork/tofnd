# tssd -- Threshold Signature Scheme Daemon

A gRPC server wrapper for the [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) library.

## Setup

`tssd` uses the [hyperium/tonic](https://github.com/hyperium/tonic) Rust gRPC implementation, which requires:
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
Terminate the server with `ctrl+C`.

The gRPC service is called `GG20`.

## Talk to the server using grpcurl

Install [grpcurl](https://github.com/fullstorydev/grpcurl) if you haven't already.

While `tssd` is running, in a separate terminal:
```
$ grpcurl -plaintext -import-path ./proto -proto tssd.proto -d '{"name": "Rick and Morty"}' [::]:50051 tssd.GG20/SayHello
```

## Initial commit: hello world

`tssd` doesn't do much yet.  The `GG20` service has only one gRPC method: `SayHello`.

Current code is based on [tonic helloworld tutorial](https://github.com/hyperium/tonic/blob/master/examples/helloworld-tutorial.md).