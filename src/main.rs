use std::{env, net::SocketAddr};
use tokio::net::TcpListener;

mod gg20;
mod kv_manager;

// gather logs; need to set RUST_LOG=info
use tracing::{info, span, Level};

// protocol buffers via tonic: https://github.com/hyperium/tonic/blob/master/examples/helloworld-tutorial.md#writing-our-server
pub mod proto {
    tonic::include_proto!("tofnd");
}

mod config;
use config::parse_args;

// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type TofndError = Box<dyn std::error::Error + Send + Sync>;

fn set_up_logs(log_level: &str, enable_colours: bool) {
    // set up environment variable for log level
    env::set_var("RUST_LOG", log_level);
    // set up an event subscriber for logs
    tracing_subscriber::fmt().with_ansi(enable_colours).init();
}

#[cfg(feature = "malicious")]
pub fn warn_for_malicious_build() {
    use tracing::warn;
    warn!("WARNING: THIS tofnd BINARY AS COMPILED IN 'MALICIOUS' MODE.  MALICIOUS BEHAVIOUR IS INTENTIONALLY INSERTED INTO SOME MESSAGES.  THIS BEHAVIOUR WILL CAUSE OTHER tofnd PROCESSES TO IDENTIFY THE CURRENT PROCESS AS MALICIOUS.");
}

#[tokio::main]
async fn main() -> Result<(), TofndError> {
    // set up log subscriber
    // TODO read arguments from a config file
    set_up_logs("INFO", atty::is(atty::Stream::Stdout));

    #[cfg(not(feature = "malicious"))]
    let (port, mnemonic_cmd) = parse_args()?;

    // print a warning log if we are running in malicious mode
    #[cfg(feature = "malicious")]
    warn_for_malicious_build();

    #[cfg(feature = "malicious")]
    let (port, mnemonic_cmd, keygen_behaviour, sign_behaviour) = parse_args()?;

    // set up span for logs
    let main_span = span!(Level::INFO, "main");
    let _enter = main_span.enter();

    let incoming = TcpListener::bind(addr(port)).await?;
    info!(
        "tofnd listen addr {:?}, use ctrl+c to shutdown",
        incoming.local_addr()?
    );

    // TODO: pass cmd from command line
    #[cfg(not(feature = "malicious"))]
    let my_service = gg20::new_service(mnemonic_cmd).await;
    #[cfg(feature = "malicious")]
    let my_service = gg20::new_service(mnemonic_cmd, keygen_behaviour, sign_behaviour).await;

    let proto_service = proto::gg20_server::Gg20Server::new(my_service);

    tonic::transport::Server::builder()
        .add_service(proto_service)
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await?;

    Ok(())
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port)) // ipv4
}

// graceful shutdown https://hyper.rs/guides/server/graceful-shutdown/
async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    info!("tofnd shutdown signal received");
}

#[cfg(test)]
mod tests;
