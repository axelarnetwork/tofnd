mod gg20;

pub mod proto {
    tonic::include_proto!("tssd");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let my_service = gg20::GG20Service;
    let proto_service = proto::gg20_server::Gg20Server::new(my_service);

    tonic::transport::Server::builder()
        .add_service(proto_service)
        .serve(addr)
        .await?;

    Ok(())
}
