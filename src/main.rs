use std::env;

mod gg20;

pub mod proto {
    tonic::include_proto!("tssd");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let port = match args.len() {
        2 => &args[1],
        _ => "50051",
    };
    let addr = format!("{}{}", "[::1]:", port).parse()?;
    println!("rust-tssd listen addr {:?}", addr);
    let my_service = gg20::GG20Service;
    let proto_service = proto::gg20_server::Gg20Server::new(my_service);

    tonic::transport::Server::builder()
        .add_service(proto_service)
        // .serve_with_shutdown(addr, shutdown_signal())
        .serve(addr)
        .await?;

    Ok(())
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
