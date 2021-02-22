use super::{addr, gg20, proto, Deliverer, Party, SenderReceiver};
use std::convert::TryFrom;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tonic::Request;

// #[derive(Debug)]
struct TofndParty {
    client: proto::gg20_client::Gg20Client<tonic::transport::Channel>,
    server_handle: JoinHandle<()>,
    server_shutdown_sender: oneshot::Sender<()>,
    server_port: u16,
}

pub(super) async fn new() -> impl Party {
    // start server
    let (server_shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();
    let my_service = gg20::new_service();
    let proto_service = proto::gg20_server::Gg20Server::new(my_service);
    let incoming = TcpListener::bind(addr(0)).await.unwrap(); // use port 0 and let the OS decide
    let server_addr = incoming.local_addr().unwrap();
    let server_port = server_addr.port();
    println!("new party bound to port [{:?}]", server_port);
    // let (startup_sender, startup_receiver) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(proto_service)
            .serve_with_incoming_shutdown(incoming, async {
                shutdown_receiver.await.unwrap();
            })
            .await
            .unwrap();
        // startup_sender.send(()).unwrap();
    });

    // TODO get the server to notify us after it's started, or perhaps just "yield" here
    // println!(
    //     "new party [{}] TODO sleep waiting for server to start...",
    //     server_port
    // );
    // tokio::time::delay_for(std::time::Duration::from_millis(100)).await;
    // startup_receiver.await.unwrap();
    // println!("party [{}] server started!", init.party_uids[my_id_index]);

    println!("new party [{}] connect to server...", server_port);
    let client = proto::gg20_client::Gg20Client::connect(format!("http://{}", server_addr))
        .await
        .unwrap();

    TofndParty {
        client,
        server_handle,
        server_shutdown_sender,
        server_port,
    }
}

#[tonic::async_trait]
impl Party for TofndParty {
    async fn execute_keygen(
        &mut self,
        init: proto::KeygenInit,
        channels: SenderReceiver,
        mut delivery: Deliverer,
    ) {
        let my_uid = init.party_uids[usize::try_from(init.my_party_index).unwrap()].clone();
        let my_display_name = format!("{}:{}", my_uid, self.server_port); // uid:port
        let (mut keygen_server_incoming, rx) = channels;
        let mut keygen_server_outgoing = self
            .client
            .keygen(Request::new(rx))
            .await
            .unwrap()
            .into_inner();

        // the first outbound message is keygen init info
        keygen_server_incoming
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::KeygenInit(init)),
            })
            .await
            .unwrap();

        while let Some(msg) = keygen_server_outgoing.message().await.unwrap() {
            let msg_type = msg.data.as_ref().expect("missing data");

            match msg_type {
                proto::message_out::Data::Traffic(_) => {
                    delivery.deliver(&msg, &my_uid).await;
                }
                proto::message_out::Data::KeygenResult(_) => {
                    println!("party [{}] keygen finished!", my_display_name);
                    break;
                }
                _ => panic!(
                    "party [{}] keygen errpr: bad outgoing message type",
                    my_display_name
                ),
            };
        }
        println!("party [{}] keygen execution complete", my_display_name);
    }

    async fn execute_sign(
        &mut self,
        init: proto::SignInit,
        channels: SenderReceiver,
        mut delivery: Deliverer,
        my_uid: &str,
    ) {
        let my_display_name = format!("{}:{}", my_uid, self.server_port); // uid:port
        let (mut sign_server_incoming, rx) = channels;
        let mut sign_server_outgoing = self
            .client
            .sign(Request::new(rx))
            .await
            .unwrap()
            .into_inner();

        // the first outbound message is keygen init info
        sign_server_incoming
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::SignInit(init)),
            })
            .await
            .unwrap();

        while let Some(msg) = sign_server_outgoing.message().await.unwrap() {
            let msg_type = msg.data.as_ref().expect("missing data");

            match msg_type {
                proto::message_out::Data::Traffic(_) => {
                    delivery.deliver(&msg, &my_uid).await;
                }
                proto::message_out::Data::SignResult(_) => {
                    println!("party [{}] sign finished!", my_display_name);
                    break;
                }
                _ => panic!(
                    "party [{}] sign error: bad outgoing message type",
                    my_display_name
                ),
            };
        }
        println!("party [{}] sign execution complete", my_display_name);
    }

    async fn shutdown(mut self) {
        self.server_shutdown_sender.send(()).unwrap(); // tell the server to shut down
        self.server_handle.await.unwrap(); // wait for server to shut down
        println!("party [{}] shutdown success", self.server_port);
    }
}
