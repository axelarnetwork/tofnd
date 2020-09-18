use tonic::transport::Server;
use grpc::gg20_server::Gg20Server;
mod gg20;
use gg20::GG20Service;

pub mod grpc {
    tonic::include_proto!("tssd");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let greeter = GG20Service::default();

    Server::builder()
        .add_service(Gg20Server::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}
