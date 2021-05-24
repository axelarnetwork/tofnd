use super::{mock::SenderReceiver, Deliverer, InitParty, Party};
use crate::{addr, gg20, proto};
use proto::message_out::SignResult;
use std::convert::TryFrom;
use std::path::Path;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tonic::Request;

// I tried to keep this struct private and return `impl Party` from new() but ran into so many problems with the Rust compiler
// I also tried using Box<dyn Party> but ran into this: https://github.com/rust-lang/rust/issues/63033
pub(super) struct TofndParty {
    db_name: String,
    client: proto::gg20_client::Gg20Client<tonic::transport::Channel>,
    server_handle: JoinHandle<()>,
    server_shutdown_sender: oneshot::Sender<()>,
    server_port: u16,
    pub expect_result: bool,
    timeout: bool,
}

impl TofndParty {
    pub(super) async fn new(init_party: InitParty, testdir: &Path, expect_result: bool) -> Self {
        let db_name = format!("test-key-{:02}", init_party.party_index);
        let db_path = testdir.join(db_name);
        let db_path = db_path.to_str().unwrap();

        // start server
        let (server_shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();

        // start service with respect to the current build
        #[cfg(not(feature = "malicious"))]
        let my_service = gg20::tests::with_db_name(&db_path);
        #[cfg(feature = "malicious")]
        let my_service = gg20::tests::with_db_name_malicious(&db_path, init_party.malicious_type);

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
            db_name: db_path.to_owned(),
            client,
            server_handle,
            server_shutdown_sender,
            server_port,
            expect_result,
            timeout: init_party.timeout,
        }
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
        let (keygen_server_incoming, rx) = channels;
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
            .unwrap();

        let mut keygen_completed = false;
        while let Some(msg) = keygen_server_outgoing.message().await.unwrap() {
            let msg_type = msg.data.as_ref().expect("missing data");

            match msg_type {
                proto::message_out::Data::Traffic(_) => {
                    delivery.deliver(&msg, &my_uid).await;
                }
                proto::message_out::Data::KeygenResult(_) => {
                    println!("party [{}] keygen finished!", my_display_name);
                    keygen_completed = true;
                    break;
                }
                _ => panic!(
                    "party [{}] keygen errpr: bad outgoing message type",
                    my_display_name
                ),
            };
        }
        assert!(keygen_completed, "keygen failure to complete");
        println!("party [{}] keygen execution complete", my_display_name);
    }

    async fn execute_sign(
        &mut self,
        init: proto::SignInit,
        channels: SenderReceiver,
        mut delivery: Deliverer,
        my_uid: &str,
    ) -> SignResult {
        let my_display_name = format!("{}:{}", my_uid, self.server_port); // uid:port
        let (sign_server_incoming, rx) = channels;
        let mut sign_server_outgoing = self
            .client
            .sign(Request::new(rx))
            .await
            .unwrap()
            .into_inner();

        // the first outbound message is sign init info
        sign_server_incoming
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::SignInit(init)),
            })
            .unwrap();

        // use Option of SignResult to avoid giving a default value to SignResult
        let mut result: Option<SignResult> = None;
        let mut msg_count: usize = 0;
        while let Some(msg) = sign_server_outgoing.message().await.unwrap() {
            let msg_type = msg.data.as_ref().expect("missing data");

            // check if I want to send abort message. This is for timeout tests
            msg_count += 1;
            if self.timeout && msg_count == 5 {
                delivery.send_timeouts().await;
            }

            match msg_type {
                proto::message_out::Data::Traffic(_) => {
                    delivery.deliver(&msg, &my_uid).await;
                }
                proto::message_out::Data::SignResult(res) => {
                    result = Some(res.clone());
                    println!("party [{}] sign finished!", my_display_name);
                    break;
                }
                _ => panic!(
                    "party [{}] sign error: bad outgoing message type",
                    my_display_name
                ),
            };
        }


        // return default value for SignResult if socket closed before I received the result
        if result.is_none() {
            println!(
                "party [{}] sign execution was not completed",
                my_display_name
            );
            return SignResult::default();
        }
        println!("party [{}] sign execution complete", my_display_name);

        result.unwrap() // it's safe to unwrap here
    }

    async fn shutdown(mut self) {
        self.server_shutdown_sender.send(()).unwrap(); // tell the server to shut down
        self.server_handle.await.unwrap(); // wait for server to shut down
        println!("party [{}] shutdown success", self.server_port);
    }

    fn get_db_path(&self) -> std::path::PathBuf {
        gg20::tests::get_db_path(&self.db_name)
    }
}
