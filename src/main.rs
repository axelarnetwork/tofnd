use std::{env, net::SocketAddr};

mod gg20;

pub mod proto {
    tonic::include_proto!("tofnd");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let port = match args.len() {
        2 => args[1].parse()?,
        _ => 50051,
    };
    let addr = addr(port)?;
    println!("tofnd listen addr {:?}", addr);
    let my_service = gg20::GG20Service;
    let proto_service = proto::gg20_server::Gg20Server::new(my_service);

    tonic::transport::Server::builder()
        .add_service(proto_service)
        // .serve_with_shutdown(addr, shutdown_signal())
        .serve(addr)
        .await?;

    Ok(())
}

fn addr(port: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    // Ok(format!("[::1]:{}", port).parse()?) // ipv6
    Ok(format!("127.0.0.1:{}", port).parse()?) // ipv4
}

// https://hyper.rs/guides/server/graceful-shutdown/
// async fn shutdown_signal() {
//     // Wait for the CTRL+C signal
//     tokio1::signal::ctrl_c()
//         .await
//         .expect("failed to install CTRL+C signal handler");
// }

#[cfg(test)]
mod tests;
