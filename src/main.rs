use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

mod encrypted_sled;
mod gg20;
mod kv_manager;

// gather logs; need to set RUST_LOG=info
use tracing::{info, span, Level};

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
        .without_time()
        .with_target(false)
        .with_current_span(false)
        .flatten_event(true) // make logs complient with datadog
        .init();
}

#[cfg(feature = "malicious")]
pub fn warn_for_malicious_build() {
    use tracing::warn;
    warn!("WARNING: THIS tofnd BINARY AS COMPILED IN 'MALICIOUS' MODE.  MALICIOUS BEHAVIOUR IS INTENTIONALLY INSERTED INTO SOME MESSAGES.  THIS BEHAVIOUR WILL CAUSE OTHER tofnd PROCESSES TO IDENTIFY THE CURRENT PROCESS AS MALICIOUS.");
}

fn warn_for_unsafe_execution() {
    use tracing::warn;
    warn!("WARNING: THIS tofnd BINARY IS NOT SAFE: SAFE PRIMES ARE NOT USED BECAUSE '--unsafe' FLAG IS ENABLED.  USE '--unsafe' FLAG ONLY FOR TESTING.");
}

/// worker_threads defaults to the number of cpus on the system
/// https://docs.rs/tokio/1.2.0/tokio/attr.main.html#multi-threaded-runtime
#[tokio::main(flavor = "multi_thread")]
async fn main() -> TofndResult<()> {
    let cfg = parse_args()?;

    // immediately read an encryption password from stdin
    let password = cfg.password_method.execute()?;

    set_up_logs();

    // print config warnings
    #[cfg(feature = "malicious")]
    warn_for_malicious_build();
    if !cfg.safe_keygen {
        warn_for_unsafe_execution();
    }

    // set up span for logs
    let main_span = span!(Level::INFO, "main");
    let _enter = main_span.enter();

    let incoming = TcpListener::bind(addr(cfg.port)).await?;
    info!(
        "tofnd listen addr {:?}, use ctrl+c to shutdown",
        incoming.local_addr()?
    );

    let cmd = cfg.mnemonic_cmd.clone();

    let kv_manager = KvManager::new(&cfg.tofnd_path, password)?
        .handle_mnemonic(&cfg.mnemonic_cmd)
        .await?;

    let gg20_service = gg20::service::new_service(cfg, kv_manager)?;

    if cmd.exit_after_cmd() {
        info!("Tofnd exited after using command <{:?}>. Run `./tofnd -m existing` to execute gRPC daemon.", cmd);
        return Ok(());
    }

    let proto_service = proto::gg20_server::Gg20Server::new(gg20_service);

    tonic::transport::Server::builder()
        .add_service(proto_service)
        .serve_with_incoming_shutdown(TcpListenerStream::new(incoming), shutdown_signal())
        .await?;

    Ok(())
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port)) // ipv4
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
