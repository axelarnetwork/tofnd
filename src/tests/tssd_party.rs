use super::{
    gg20,
    mock::{Deliverer, Party},
    proto,
};
use std::{print, thread};

// use futures::channel::oneshot::Sender;
use futures_util::{future::Future, FutureExt};
use tokio::task::JoinHandle;

pub struct TssdParty<'a> {
    transport: &'a dyn Deliverer,
    // server: Box<Future<Output = Result<(), tonic::transport::Error>>>,
    shutdown_sender: tokio::sync::oneshot::Sender<()>,
    server_handle: JoinHandle<()>,
}

impl<'a> TssdParty<'a> {
    // #[allow(clippy::new_ret_no_self)]
    // return `impl Party` instead of `Self`
    // why do we need `'_`? https://github.com/rust-lang/rust/issues/51282
    // pub async fn new(init: &proto::KeygenInit, transport: &'a impl Deliverer) -> impl Party + 'a {
    pub async fn new(init: &proto::KeygenInit, transport: &'a impl Deliverer) -> TssdParty<'a> {
        let (my_id_index, threshold) = gg20::keygen_check_args(&init).unwrap();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

        // TODO set port 0 and let the OS decide
        let addr = format!("{}{}", "[::1]:", 50051 + my_id_index)
            .parse()
            .unwrap();
        println!(
            "party [{}] grpc addr {:?}",
            init.party_uids[my_id_index], addr
        );
        let my_service = gg20::GG20Service;
        let proto_service = proto::gg20_server::Gg20Server::new(my_service);

        let server_handle = tokio::spawn(async move {
            println!("tokio:spawn start");
            let res = tonic::transport::Server::builder()
                .add_service(proto_service)
                .serve_with_shutdown(addr, async {
                    println!("waiting for server shutdown...");
                    shutdown_receiver.await.ok();
                    println!("server shutdown complete!");
                })
                .await;
            println!("tokio:spawn return {:?}", res);
        });
        // .await;

        // println!("sleep for 5 secs...");
        // tokio::time::delay_for(std::time::Duration::from_secs(5)).await;

        // match shutdown_sender.send(()) {
        //     Ok(f) => println!("shutdown Ok: {:?}", f),
        //     Err(f) => println!("shutdown Err: {:?}", f),
        // }

        // tokio::time::delay_for(std::time::Duration::from_secs(5)).await;

        Self {
            transport,
            shutdown_sender,
            server_handle,
        }
    }
}

#[tonic::async_trait]
impl Party for TssdParty<'_> {
    fn execute(&self) {}
    fn msg_in(&self, msg: &proto::MessageIn) {}
    async fn close(self) {
        match self.shutdown_sender.send(()) {
            Ok(f) => println!("close Ok: {:?}", f),
            Err(f) => println!("close Err: {:?}", f),
        }
        self.server_handle.await;
    }
}
