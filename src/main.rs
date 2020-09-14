use tonic::{transport::Server, Request, Response, Status};

use tssd::gg20_server::{Gg20, Gg20Server};
use tssd::{HelloReply, HelloRequest};

pub mod tssd {
    tonic::include_proto!("tssd");
}

#[derive(Debug, Default)]
pub struct GG20Service;

#[tonic::async_trait]
impl Gg20 for GG20Service {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = tssd::HelloReply {
            message: format!("Hello {}!", request.into_inner().name).into(),
        };

        Ok(Response::new(reply))
    }
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