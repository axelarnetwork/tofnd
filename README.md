# tofnd: A cryptographic signing service

Tofnd is a [gRPC](https://grpc.io/) server written in Rust that wraps the [tofn](https://github.com/axelarnetwork/tofn) cryptography library.

## Setup

The gRPC protobuf file is a separate [submodule](https://github.com/axelarnetwork/grpc-protobuf/). To fetch it, please be sure that the `--recursive` flag is enabled:

```bash
git clone git@github.com:axelarnetwork/tofnd.git --recursive
```

## Build binaries

Pre-built releases can be found [here](https://github.com/axelarnetwork/tofnd/releases)

To build yourself, run:

```bash
cargo build --release --locked
```

## Running the server

```bash
# install tofnd at ./target/release/tofnd
cargo install --locked --path . && cd ./target/release

# init tofnd
./tofnd -m create

# IMPORTANT: store the content of ./.tofnd/export file at a safe, offline place, and then delete the file
rm ./.tofnd/export

# start tofnd daemon
./tofnd
```

Terminate the server with `ctrl+C`.

## Password

By default, `tofnd` prompts for a password from stdin immediately upon launch.  This password is used to encrypt on-disk storage.  It is the responsibility of the user to keep this password safe.

Users may automate password entry as they see fit.  Some examples follow.  These examples are not necessarily secure as written---it's the responsibility of the user to secure password entry.

```bash
# feed password from MacOS keyring
security find-generic-password -a $(whoami) -s "tofnd" -w | ./tofnd

# feed password from 1password-cli
op get item tofnd --fields password | ./tofnd

# feed password from Pass
pass show tofnd | ./tofnd

# feed password from environment variable `PASSWORD`
echo $PASSWORD | ./tofnd

# feed password from a file `password.txt`
cat ./password.txt | ./tofnd
```

Sophisticated users may explicitly opt out of password entry via the `--no-password` terminal argument (see below).  In this case, on-disk storage is not secure---it is the responsibility of the user to take additional steps to secure on-disk storage.

## Command line arguments

We use [clap](https://clap.rs/) to manage command line arguments.

Users can specify:

1. Tofnd's root folder. Use `--directory` or `-d` to specify a full or a relative path. If no argument is provided, then the environment variable `TOFND_HOME` is used. If no environment variable is set either, the default `./tofnd` directory is used.
2. The port number of the gRPC server (default is 50051).
3. `mnemonic` operations for their `tofnd` instance (default is `Existing`).
For more information, see on mnemonic options, see [Mnemonic](#mnemonic).
4. By default, `tofnd` expects a password from the standard input. Users that don't want to use passwords can use the `--no-password` flag. **Attention: Use `--no-password` only for testing .**

```text
A cryptographic signing service

USAGE:
    tofnd [FLAGS] [OPTIONS]

FLAGS:
        --no-password    Skip providing a password. Disabled by default. **Important note** If --no-password is set, the
                         a default (and public) password is used to encrypt.
    -h, --help           Prints help information
    -V, --version        Prints version information

OPTIONS:
    -a, --address <ip>              [default: 0.0.0.0]
    -d, --directory <directory>     [env: TOFND_HOME=]  [default: .tofnd]
    -m, --mnemonic <mnemonic>       [default: existing]  [possible values: existing, create, import, export]
    -p, --port <port>               [default: 50051]
```

## Docker

### Docker Setup

To setup a `tofnd` container, use the `create` mnemonic command:

```bash
docker-compose run -e MNEMONIC_CMD=create tofnd
```

This will initialize `tofnd`, and then exit.

### Execution

To run a `tofnd` daemon inside a container, run:

```bash
docker-compose up
```

### Storage

We use [data containers](https://docs.docker.com/engine/reference/commandline/volume_create/) to persist data across restarts. To clean up storage, remove all `tofnd` containers, and run

```bash
docker volume rm tofnd_tofnd
```

### Testing

For testing purposes, `docker-compose.test.yml` is available, which is equivelent to `./tofnd --no-password`. To spin up a test `tofnd` container, run

```bash
docker-compose -f docker-compose.test.yml up
```

### The `auto` command

In containerized environments the `auto` mnemonic command can be used.  This command is implemented in `entrypoint.sh` and does the following:

1. Try to use existing mnemonic.  If successful then launch `tofnd` server.
2. Try to import a mnemonic from file.  If successful then launch `tofnd` server.
3. Create a new mnemonic.  The newly created mnemonic is automatically written to the file `TOFND_HOME/export`---rename this file to `TOFND_HOME/import` so as to unblock future executions of tofnd.  Then launch `tofnd` server.

The rationale behind `auto` is that users can frictionlessly launch and restart their tofnd nodes without the need to execute multiple commands.
`auto` is currently the default command only in `docker-compose.test.yml`, but users can edit the `docker-compose.yml` to use it at their own discretion.

**Attention:** `auto` leaves the mnemonic on plain text on disk. You should remove the `TOFND_HOME/import` file and store the mnemonic at a safe, offline place.

## Mnemonic

`Tofnd` uses the [tiny-bip39](https://docs.rs/crate/tiny-bip39) crate to enable users manage mnemonic passphrases. Currently, each party can use only one passphrase.

### Mnemonic options

The command line API supports the following commands:

* `Existing` Starts the gRPC daemon using an existing mnemonic; Fails if no mnemonic exist.

* `Create` Creates a new mnemonic, inserts it in the kv-store, exports it to a file and exits; Fails if a mnemonic already exists.

* `Import` Prompts user to give a new mnemonic from standard input, inserts it in the kv-store and exits; Fails if a mnemonic exists or if the provided string is not a valid bip39 mnemonic.

* `Export` Writes the existing mnemonic to _<tofnd_root>/.tofnd/export_ and exits; Succeeds when there is an existing mnemonic. Fails if no mnemonic is stored, or the export file already exists.

## Zeroization

We use the [zeroize](https://docs.rs/zeroize/1.1.1/zeroize/) crate to clear sensitive info for memory as a good practice. The data we clean are related to the mnemonic:

1. entropy
2. passwords

Note that, [tiny-bip39](https://docs.rs/crate/tiny-bip39) also uses `zeroize` internally.

## KV Store

To persist information between different gRPCs (i.e. _keygen_ and _sign_), we use a key-value storage based on [sled](https://sled.rs/).

`Tofnd` uses an encrypted mnemonic KV Store which stores the entropy of a mnemonic passphrase. This entropy is used to derive user's keys. The KV Store is encrypted with a password provided by the user. The password is used to derive a key that encrypts the KV Store.

## Threshold cryptography

For an implementation of the [GG20](https://eprint.iacr.org/2020/540.pdf) threshold-ECDSA protocol,
see this version of [tofnd](https://github.com/axelarnetwork/tofnd/tree/v0.10.1). The GG20 protocol implementation should not be considered ready for production since it doesn't protect against recently discovered attacks on the protocol implementation. This was removed from `tofnd` as it is not being used in the Axelar protocol.

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
