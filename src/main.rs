use multisig::service::MultisigService;
use proto::multisig_server::MultisigServer;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

mod encrypted_sled;
mod kv_manager;
mod mnemonic;
mod multisig;

// gather logs; need to set RUST_LOG=info
use tracing::{info, span, warn, Level};

// error handling
pub type TofndResult<Success> = anyhow::Result<Success>;

// protocol buffers via tonic: https://github.com/hyperium/tonic/blob/master/examples/helloworld-tutorial.md#writing-our-server
pub mod proto {
    tonic::include_proto!("tofnd");
}

mod config;
use config::parse_args;

use crate::kv_manager::KvManager;

fn set_up_logs() {
    // enable only tofnd and tofn debug logs - disable serde, tonic, tokio, etc.
    tracing_subscriber::fmt()
        .with_env_filter("tofnd=debug,tofn=debug")
        .json()
        .with_ansi(atty::is(atty::Stream::Stdout))
        .with_target(false)
        .with_current_span(false)
        .flatten_event(true) // make logs complient with datadog
        .init();
}

/// worker_threads defaults to the number of cpus on the system
/// https://docs.rs/tokio/1.2.0/tokio/attr.main.html#multi-threaded-runtime
#[tokio::main(flavor = "multi_thread")]
async fn main() -> TofndResult<()> {
    set_up_logs(); // can't print any logs until they're set up
    let cfg = parse_args()?;
    let socket_address = addr(&cfg.ip, cfg.port)?;

    // The gRPC server is plaintext and unauthenticated: any caller that can
    // reach the port can request signatures for every key this daemon holds.
    // Loopback binds keep that power on the local machine, but a non-loopback
    // bind exposes a signing oracle to the network. Warn loudly so exposing it
    // is a deliberate operator choice rather than a silent configuration slip.
    if !socket_address.ip().is_loopback() {
        warn!(
            "tofnd is binding to {}, which is not a loopback address: the gRPC              service is plaintext and unauthenticated, so any party that can              reach this port can request signatures with this validator's keys.              Restrict network access to this port.",
            socket_address.ip()
        );
    }

    // immediately read an encryption password from stdin
    let password = cfg.password_method.execute()?;

    // set up span for logs
    let main_span = span!(Level::INFO, "main");
    let _enter = main_span.enter();
    let cmd = cfg.mnemonic_cmd.clone();

    // this step takes a long time due to password-based decryption
    let kv_manager = KvManager::new(cfg.tofnd_path.clone(), password)?
        .handle_mnemonic(&cfg.mnemonic_cmd)
        .await?;

    if cmd.exit_after_cmd() {
        info!("Tofnd exited after using command <{:?}>. Run `./tofnd -m existing` to execute gRPC daemon.", cmd);
        return Ok(());
    }

    let service = MultisigServer::new(MultisigService::new(kv_manager));

    let incoming = TcpListener::bind(socket_address).await?;
    info!(
        "tofnd listen addr {:?}, use ctrl+c to shutdown",
        incoming.local_addr()?
    );

    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(TcpListenerStream::new(incoming), shutdown_signal())
        .await?;

    Ok(())
}

fn addr(ip: &str, port: u16) -> TofndResult<SocketAddr> {
    let socket_addr = format!("{}:{}", ip, port);
    socket_addr
        .parse::<SocketAddr>()
        .map_err(|err| anyhow::anyhow!(err))
}

// graceful shutdown https://hyper.rs/guides/server/graceful-shutdown/
// can't use Result<> here because `serve_with_incoming_shutdown` expects F: Future<Output = ()>,
async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    info!("tofnd shutdown signal received");
}

#[cfg(test)]
mod tests;
