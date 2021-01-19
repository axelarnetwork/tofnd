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

// #[derive(Debug)]
pub struct TssdParty<'a> {
    transport: &'a dyn Deliverer,
    // shutdown_sender: tokio::sync::oneshot::Sender<()>,
    // server_handle: JoinHandle<Result<(), tonic::transport::Error>>,
    server: Option<(
        JoinHandle<Result<(), tonic::transport::Error>>,
        tokio::sync::oneshot::Sender<()>,
    )>, // (server_handle, shutdown_sender)
    server_addr: SocketAddr,
    keygen_init: proto::KeygenInit,
    my_id_index: usize, // sanitized from keygen_init
    threshold: usize,   // sanitized from keygen_init
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
            transport: transport,
            server: Some((server_handle, shutdown_sender)),
            // shutdown_sender,
            // server_handle,
            server_addr,
            keygen_init: init.clone(),
            my_id_index,
            threshold,
            to_server: None,
        }
    }
}

#[tonic::async_trait]
impl Party for TssdParty<'_> {
    fn get_id(&self) -> &str {
        &self.keygen_init.party_uids[self.my_id_index]
    }

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

        // let outbound = async_stream::try_stream! {
        //     yield proto::MessageIn {
        //         data: Some(proto::message_in::Data::KeygenInit(
        //             self.keygen_init.clone(), // TODO clone
        //         )),
        //     };
        // };

        let (mut to_server, rx) = tokio::sync::mpsc::channel(4);
        // to_server.clone();
        self.to_server = Some(to_server);
        // let transport = self.transport.take().as_ref().unwrap();
        // let my_id = self.get_id().to_string();
        println!("calling keygen...");
        // let execution_handle = tokio::spawn(async move {
        let mut from_server = client.keygen(Request::new(rx)).await.unwrap().into_inner();
        println!("keygen returned! sending keygen init msg...");

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
        println!("init msg returned! entering message loop...");

        while let Some(msg) = from_server.message().await.unwrap() {
            // println!("outgoing msg: {:?}", msg);
            let msg_type = msg.data.as_ref().expect("missing data");
            match msg_type {
                proto::message_out::Data::Traffic(_) => self.transport.deliver(&msg, self.get_id()),
                proto::message_out::Data::KeygenResult(_) => {
                    println!("received keygen result from server!  breaking from message loop...");
                    break;
                }
                _ => panic!("bad outgoing message type"),
            };
        }
        println!("keygen finished!");
    }

    async fn msg_in(&mut self, msg: &proto::MessageIn) {
        // sanity checks and debug info
        {
            let msg = msg.data.as_ref().expect("missing data");
            let msg = match msg {
                proto::message_in::Data::Traffic(t) => t,
                _ => panic!("all incoming messages must be traffic in"),
            };
            println!(
                "incoming msg from [{}] to me [{}] broadcast?? [{}]",
                msg.from_party_uid,
                self.get_id(),
                msg.is_broadcast
            );
        }
        self.to_server
            .as_mut()
            .expect("party is not executing")
            .send(msg.clone())
            .await
            .unwrap();
    }

    async fn close(&mut self) {
        let my_id = self.get_id().to_string(); // fighting the borrow checker
        let (server_handle, shutdown_sender) = self.server.take().expect("missing server");
        shutdown_sender.send(()).unwrap(); // tell the server to shut down
        server_handle.await.unwrap().unwrap(); // wait for server to shut down
        println!("party [{}] shutdown success", my_id);
    }
}
