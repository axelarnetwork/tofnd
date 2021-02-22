use std::{env, net::SocketAddr};
use tokio::net::TcpListener;

mod gg20;
mod kv_manager;

// protocol buffers via tonic: https://github.com/hyperium/tonic/blob/master/examples/helloworld-tutorial.md#writing-our-server
pub mod proto {
    tonic::include_proto!("tofnd");
}

// TODO make a custom error type https://github.com/tokio-rs/mini-redis/blob/c3bc304ac9f4b784f24b7f7012ed5a320594eb69/src/lib.rs#L58-L69
type TofndError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), TofndError> {
    let args: Vec<String> = env::args().collect();
    let port: u16 = match args.len() {
        2 => args[1].parse()?,
        _ => 50051, // default listen port
    };
    let incoming = TcpListener::bind(addr(port)).await?;
    println!("tofnd listen addr {:?}", incoming.local_addr()?);
    let my_service = gg20::new_service();
    let proto_service = proto::gg20_server::Gg20Server::new(my_service);

    tonic::transport::Server::builder()
        .add_service(proto_service)
        // .serve_with_shutdown(addr, shutdown_signal())
        // .serve(addr)
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

fn addr(port: u16) -> SocketAddr {
    // Ok(format!("[::1]:{}", port).parse()?) // ipv6
    // Ok(format!("0.0.0.0:{}", port).parse()?) // ipv4
    SocketAddr::from(([0, 0, 0, 0], port))
}

// TODO graceful shutdown
// https://hyper.rs/guides/server/graceful-shutdown/
// async fn shutdown_signal() {
//     // Wait for the CTRL+C signal
//     tokio1::signal::ctrl_c()
//         .await
//         .expect("failed to install CTRL+C signal handler");
// }

#[cfg(test)]
mod tests;
