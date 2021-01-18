use super::{
    gg20,
    mock::{Deliverer, Party},
    proto,
};
use std::{net::SocketAddr, print, thread};

// use futures::channel::oneshot::Sender;
use futures_util::{future::Future, FutureExt};
use tokio::{sync::mpsc::Sender, task::JoinHandle};
use tonic::Request;

pub struct TssdParty<'a> {
    transport: &'a dyn Deliverer,
    shutdown_sender: tokio::sync::oneshot::Sender<()>,
    server_handle: JoinHandle<Result<(), tonic::transport::Error>>,
    server_addr: SocketAddr,
    keygen_init: proto::KeygenInit,
    to_server: Option<Sender<proto::MessageIn>>,
}

impl<'a> TssdParty<'a> {
    pub async fn new(init: &proto::KeygenInit, transport: &'a impl Deliverer) -> TssdParty<'a> {
        let (my_id_index, threshold) = gg20::keygen_check_args(&init).unwrap();

        // start server
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let server_addr = format!("{}{}", "[::1]:", 50051 + my_id_index) // TODO set port 0 and let the OS decide
            .parse()
            .unwrap();
        println!(
            "party [{}] grpc addr {:?}",
            init.party_uids[my_id_index], server_addr
        );
        let my_service = gg20::GG20Service;
        let proto_service = proto::gg20_server::Gg20Server::new(my_service);
        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(proto_service)
                .serve_with_shutdown(server_addr, async {
                    shutdown_receiver.await.ok();
                })
                .await
        });

        // TODO get the server to notify us after it's started, or perhaps just "yield" here
        println!("TODO wait for server to start...");
        tokio::time::delay_for(std::time::Duration::from_millis(100)).await;

        Self {
            transport,
            shutdown_sender,
            server_handle,
            server_addr,
            keygen_init: init.clone(),
            to_server: None,
        }
    }
}

#[tonic::async_trait]
impl Party for TssdParty<'_> {
    async fn execute(&mut self) {
        let mut client =
            proto::gg20_client::Gg20Client::connect(format!("http://{}", self.server_addr))
                .await
                .unwrap();

        // test call to get_key
        let get_key_response = client
            .get_key(tonic::Request::new(proto::Uid {
                uid: "test-call-to-get-key".to_string(),
            }))
            .await
            .unwrap();
        println!("get_key response: {:?}", get_key_response);

        let (mut to_server, rx) = tokio::sync::mpsc::channel(4);
        self.to_server = Some(to_server);
        println!("about to call keygen");
        let execution_handle = tokio::spawn(async move {
            let mut from_server = client.keygen(Request::new(rx)).await.unwrap().into_inner();
            while let Some(msg) = from_server.message().await.unwrap() {
                println!("outgoing msg: {:?}", msg);
            }
        });
        println!("called keygen, sending init message");

        // the first outbound message is keygen init info
        self.to_server
            .as_mut()
            .unwrap()
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::KeygenInit(
                    self.keygen_init.clone(), // TODO clone
                )),
            })
            .await
            .unwrap();

        println!("waiting for keygen to finish...");
        execution_handle.await.unwrap();
        println!("keygen finished!");
    }

    async fn msg_in(&mut self, msg: &proto::MessageIn) {
        println!("incoming msg {:?}", msg);
        self.to_server
            .as_mut()
            .expect("party is not executing")
            .send(msg.clone())
            .await
            .unwrap();
    }

    async fn close(self) {
        // match self.shutdown_sender.send(()) {
        //     Ok(f) => println!("close Ok: {:?}", f),
        //     Err(f) => println!("close Err: {:?}", f),
        // }
        self.shutdown_sender.send(()).unwrap(); // tell the server to shut down
        self.server_handle.await.unwrap().unwrap(); // wait for server to shut down
        println!("success: server shutdown");
    }
}
