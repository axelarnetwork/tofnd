# Tofnd: A gRPC threshold signature scheme daemon

Tofnd is a [gRPC](https://grpc.io/) server written in Rust that wraps the [tofn](https://github.com/axelarnetwork/tofn) threshold cryptography library.

# Setup

The gRPC protobuf file is a separate [submodule](https://github.com/axelarnetwork/grpc-protobuf/). To fetch it, please be sure that the `--recursive` flag is enabled:
```
git clone git@github.com:axelarnetwork/tofnd.git --recursive
```

`tofnd` uses the [hyperium/tonic](https://github.com/hyperium/tonic) Rust gRPC implementation, which requires:
* Rust `1.39` or greater for the `async_await` feature
    ```
    $ rustup update
    ```
* `rustfmt` to tidy up the code it generates
    ```
    $ rustup component add rustfmt
    ```

To run `tofnd` you are going to need
1. Latest stable [Rust](https://www.rust-lang.org/) language version (currently 1.53.0).
2. Clone this repo.

# Running the server

```
$ cargo run
```

Terminate the server with `ctrl+C`.

## Command line arguments

We use [clap](https://clap.rs/) to manage command line arguments.

Users can specify:
1. The port number of the gRPC server (default is 50051).
2. The `mnemonic` operation for their `tofnd` instance (default is `Create`).
For more information on mnemonic options, see [Mnemonic](#mnemonic).

```
$ cargo run -- -h

USAGE:
    tofnd [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -m, --mnemonic <mnemonic>     [default: create]  [possible values: stored, create, import, update, export]
    -p, --port <port>             [default: 50051]
```

# Mnemonic

Tofnd uses the [tiny-bip39](https://docs.rs/crate/tiny-bip39/0.8.0) crate to enable users manage mnemonic passphrases. Currently, each party can use only one passphrase.

The mnemonic is used to enable _recovery_ of shares in case of unexpected loss. See more under the [Recover](#Recover) sections.

## Mneminic options
The command line API supports the following commands:

* `Noop` does nothing and always succeeds; useful when the container restarts with the same mnemonic.  

* `Create` creates a new mnemonic; Succeeds when there is no other mnemonic already imported, fails otherwise. The new passphrase is written in a file named "./export".

* `Import` adds a new mnemonic from file "./import" file; Succeeds when there is no other mnemonic already imported, fails otherwise.

* `Export` writes the existing mnemonic to file "./export"; Succeeds when there is an existing mnemonic, fails otherwise. 

* `Update` updates existing mnemonic from file "./import"; Succeeds when there is an existing mnemonic, fails otherwise. The old passphrase is written to file "./export".

# KV Store
To persist information between different gRPCs (i.e. keygen and sign), we use a key-value storage based on [sled](https://sled.rs/).

Tofnd uses two separate KV Stores:
1. `Share KV Store`. Stores all user's shares when `keygen` protocol is completed, and uses them for `sign` protocol.
2. `Mnemonic KV Store`. Stores the entropy of a mnemonic passphrase. This entropy is used to encrypt and decrypt users' sensitive info, i.e. the content of the `Share KV Store`.

## Security
Imporant note: Currently, KV Stores are **not** encrypted. All information is stored in clear text on disk.

# gRPCs
Tofnd currently supports the following gRPCs: `keygen`, `sign` and `recover`.

`Keygen` and `sign` use [bidirectional streaming](https://grpc.io/docs/what-is-grpc/core-concepts/#bidirectional-streaming-rpc) and `Recover` is [unary](https://grpc.io/docs/what-is-grpc/core-concepts/#bidirectional-streaming-rpc).

## Keygen 
The keygen gRPC runs the keygen protocol described in [GG20](https://eprint.iacr.org/2020/540.pdf).

A successful keygen protocol returns the `public key` of the party, and the `share` information that is associated with the current keygen session. The `public key` is sent to the gRPC client, while the `share` info is encrypted and stored at the `Share KV Store` along with other non-sensitive, useful data (i.e. uids of participants, shares per party, etc).

### File structure
The keygen protocol is implemented in [tofnd/src/gg20/keygen](https://github.com/axelarnetwork/tofnd/tree/recovery-api/src/gg20/keygen), which has the following file structure:

```
├── keygen
│   ├── mod.rs
│   ├── init.rs
│   ├── execute.rs
│   ├── result.rs
│   └── types.rs
```

* In `init.rs`, the verification and sanitization of `Keygen Init` message is handled.
* In `execute.rs`, the execution of the protocol is actualized.
* In `result.rs`, the results of the keygen protocol are aggregated, validated and sent to the gRPC client.
* In `types.rs`, useful structs that are needed in the rest of the modules are defined.

## Sign
The `sign` gRPC runs a keygen protocol as described in the [GG20](https://eprint.iacr.org/2020/540.pdf) paper.

At the beginning of `sign`, the `share KV Store` is searched for data that were generated a previous keygen. A successful completion of the sign protocol returns the `signature` of the party, which is sent to the gRPC client.

### File structure
Sign's file structre is analogous to keygen's:

```
├── sign 
│   ├── mod.rs
│   ├── init.rs
│   ├── execute.rs
│   ├── result.rs
│   └── types.rs
```

* In `init.rs`, the verification and sanitization of `Sign Init` message is handled. `Sign Init` contains the `session id` of the keygen it is assossiated with. That `session id` is the key inside the `Share KV Store` that corresponds to the `share` needed for the current sign.
* In `execute.rs`, the execution of the protocol is actualized.
* In `result.rs`, the results of the keygen protocol are aggregated, validated and sent to the gRPC client.
* In `types.rs`, useful structs that are needed in the rest of the modules are defined.


### Message flows of keygen and sign 

See [keygen]() and [sign]() diagrams of detailed message flow of each protocol. Note that the diagrams contain links which will point you to the code block in which the underlying item is implemented.

## Recover

Tofnd implements key-recovery feature. When a `keygen` is completed, a `SecretKeyShare` struct is created for each one of the party's shares. These `SecretKeyShare`s are encrypted and stored in `Share KV Store` and are used for subsequent `sign`s. 

In case of sudden data loss, for example due to a hard disk crash, parties are able to recover their shares. This is possible because each party sends it's encrypted secret info to the client before storing it inside the `Share KV Store`.

# Testing

```
$ cargo test
```

# Malicious behaviours