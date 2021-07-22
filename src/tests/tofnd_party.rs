use super::{mock::SenderReceiver, Deliverer, InitParty, Party};
use crate::{
    addr,
    gg20::{self, mnemonic::Cmd},
    proto,
};
use proto::message_out::{KeygenResult, SignResult};
use std::convert::TryFrom;
use std::path::Path;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::{TcpListenerStream, UnboundedReceiverStream};
use tonic::Request;

use tracing::{info, warn};

#[cfg(feature = "malicious")]
use super::malicious::PartyMaliciousData;

// I tried to keep this struct private and return `impl Party` from new() but ran into so many problems with the Rust compiler
// I also tried using Box<dyn Party> but ran into this: https://github.com/rust-lang/rust/issues/63033
pub(super) struct TofndParty {
    db_name: String,
    client: proto::gg20_client::Gg20Client<tonic::transport::Channel>,
    server_handle: JoinHandle<()>,
    server_shutdown_sender: oneshot::Sender<()>,
    server_port: u16,
    #[cfg(feature = "malicious")]
    pub(super) malicious_data: PartyMaliciousData,
}

impl TofndParty {
    pub(super) async fn new(init_party: InitParty, mnemonic_cmd: Cmd, testdir: &Path) -> Self {
        let db_name = format!("test-key-{:02}", init_party.party_index);
        let db_path = testdir.join(db_name);
        let db_path = db_path.to_str().unwrap();

        // start server
        let (server_shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();

        // start service with respect to the current build
        let my_service = gg20::service::tests::with_db_name(
            &db_path,
            mnemonic_cmd,
            #[cfg(feature = "malicious")]
            #[cfg(feature = "malicious")]
            init_party.malicious_data.keygen_behaviour.clone(),
            // TODO: cahnge hard-coded honest
            #[cfg(feature = "malicious")]
            tofn::refactor::sign::malicious::Behaviour::Honest,
            // init_party.malicious_data.sign_behaviour.clone(),
        )
        .await;

        let proto_service = proto::gg20_server::Gg20Server::new(my_service);
        let incoming = TcpListener::bind(addr(0)).await.unwrap(); // use port 0 and let the OS decide
        let server_addr = incoming.local_addr().unwrap();
        let server_port = server_addr.port();
        info!("new party bound to port [{:?}]", server_port);
        // let (startup_sender, startup_receiver) = tokio::sync::oneshot::channel::<()>();
        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(proto_service)
                .serve_with_incoming_shutdown(TcpListenerStream::new(incoming), async {
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

        info!("new party [{}] connect to server...", server_port);
        let client = proto::gg20_client::Gg20Client::connect(format!("http://{}", server_addr))
            .await
            .unwrap();

        TofndParty {
            db_name: db_path.to_owned(),
            client,
            server_handle,
            server_shutdown_sender,
            server_port,
            #[cfg(feature = "malicious")]
            malicious_data: init_party.malicious_data,
        }
    }
}

// r1 -> bcast
// r2 -> bcast
// r3 -> bcast + p2ps
// r4 -> bcast
fn keygen_round(msg_count: usize, all_share_counts: usize, my_share_count: usize) -> usize {
    let bcast = 1;
    let p2ps = all_share_counts - 1;

    let r1_msgs = bcast;
    let r2_msgs = r1_msgs + bcast;
    let r3_msgs = r2_msgs + bcast + p2ps;
    let r4_msgs = r3_msgs + bcast;

    // multiply by my share count
    let r1_msgs = r1_msgs * my_share_count;
    let r2_msgs = r2_msgs * my_share_count;
    let r3_msgs = r3_msgs * my_share_count;
    let r4_msgs = r4_msgs * my_share_count;

    let last = r4_msgs + my_share_count; // n bcasts and n(n-1) p2ps

    if 1 <= msg_count && msg_count <= r1_msgs {
        return 1;
    } else if r1_msgs < msg_count && msg_count <= r2_msgs {
        return 2;
    } else if r2_msgs < msg_count && msg_count <= r3_msgs {
        return 3;
    } else if r3_msgs < msg_count && msg_count <= r4_msgs {
        return 4;
    }
    panic!("message counter overflow: {}. Max is {}", msg_count, last);
}

// r1 -> bcast + p2ps
// r2 -> p2ps
// r3 -> bcast
// r4 -> bcast
// r5 -> bcast + p2ps
// r6 -> bcast
// r7 -> bcast
fn sign_round(msg_count: usize, all_share_counts: usize, my_share_count: usize) -> usize {
    let bcast = 1;
    let p2ps = all_share_counts - 1;

    let r1_msgs = bcast + p2ps;
    let r2_msgs = r1_msgs + p2ps;
    let r3_msgs = r2_msgs + bcast;
    let r4_msgs = r3_msgs + bcast;
    let r5_msgs = r4_msgs + bcast + p2ps;
    let r6_msgs = r5_msgs + bcast;
    let r7_msgs = r6_msgs + bcast;
    let r8_msgs = r7_msgs + bcast;

    // multiply by my share count
    let r1_msgs = r1_msgs * my_share_count;
    let r2_msgs = r2_msgs * my_share_count;
    let r3_msgs = r3_msgs * my_share_count;
    let r4_msgs = r4_msgs * my_share_count;
    let r5_msgs = r5_msgs * my_share_count;
    let r6_msgs = r6_msgs * my_share_count;
    let r7_msgs = r7_msgs * my_share_count;

    let last = r4_msgs + my_share_count; // n bcasts and n(n-1) p2ps

    let mut round = 0;
    if 1 <= msg_count && msg_count <= r1_msgs {
        round = 1;
    } else if r1_msgs < msg_count && msg_count <= r2_msgs {
        round = 2;
    } else if r2_msgs < msg_count && msg_count <= r3_msgs {
        round = 3;
    } else if r3_msgs < msg_count && msg_count <= r4_msgs {
        round = 4;
    } else if r4_msgs < msg_count && msg_count <= r5_msgs {
        round = 5;
    } else if r5_msgs < msg_count && msg_count <= r6_msgs {
        round = 6;
    } else if r6_msgs < msg_count && msg_count <= r7_msgs {
        round = 7;
    } else if r7_msgs < msg_count && msg_count <= r8_msgs {
        round = 8;
    }
    // if we got a round from message count successfully, then add keygen rounds to it
    if round != 0 {
        let keygen_rounds = 4;
        return round + keygen_rounds;
    }

    // TODO: support multiple shares for sign. For now, return something that is not 0.
    // panic!("message counter overflow: {}. Max is {}", msg_count, last); // this info should be a panic

    // return something that won't trigger a timeout in non-timeout malicous cases with multiple shares
    return usize::MAX;
}

#[tonic::async_trait]
impl Party for TofndParty {
    async fn execute_keygen(
        &mut self,
        init: proto::KeygenInit,
        channels: SenderReceiver,
        mut delivery: Deliverer,
    ) -> KeygenResult {
        let my_uid = init.party_uids[usize::try_from(init.my_party_index).unwrap()].clone();
        let (keygen_server_incoming, rx) = channels;
        let mut keygen_server_outgoing = self
            .client
            .keygen(Request::new(UnboundedReceiverStream::new(rx)))
            .await
            .unwrap()
            .into_inner();

        let all_share_count = {
            if init.party_share_counts.len() == 0 {
                init.party_uids.len()
            } else {
                init.party_share_counts.iter().sum::<u32>() as usize
            }
        };
        let my_share_count = {
            if init.party_share_counts.len() == 0 {
                1
            } else {
                init.party_share_counts[init.my_party_index as usize] as usize
            }
        };
        // the first outbound message is keygen init info
        keygen_server_incoming
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::KeygenInit(init)),
            })
            .unwrap();

        let mut result: Option<KeygenResult> = None;
        let mut msg_count = 1;
        while let Some(msg) = keygen_server_outgoing.message().await.unwrap() {
            info!(
                "{} message {} in round {}",
                my_uid,
                msg_count,
                keygen_round(msg_count, all_share_count, my_share_count)
            );
            let msg_type = msg.data.as_ref().expect("missing data");

            match msg_type {
                #[allow(clippy::unused)] // allow unsused traffin in non malicious
                proto::message_out::Data::Traffic(traffic) => {
                    // in malicous case, if we are stallers we skip the message
                    #[cfg(feature = "malicious")]
                    {
                        let round = keygen_round(msg_count, all_share_count, my_share_count);
                        if self.malicious_data.timeout_round == round {
                            warn!("{} is stalling a message in round {}", my_uid, round);
                            continue; // tough is the life of the staller
                        }
                        if self.malicious_data.disrupt_round == round {
                            warn!("{} is disrupting a message in round {}", my_uid, round);
                            let mut t = traffic.clone();
                            t.payload = traffic.payload[0..traffic.payload.len() / 2].to_vec();
                            let mut m = msg.clone();
                            m.data = Some(proto::message_out::Data::Traffic(t));
                            delivery.deliver(&m, &my_uid);
                        }
                    }
                    delivery.deliver(&msg, &my_uid);
                }
                proto::message_out::Data::KeygenResult(res) => {
                    result = Some(res.clone());
                    info!("party [{}] keygen finished!", my_uid);
                    break;
                }
                _ => panic!("party [{}] keygen error: bad outgoing message type", my_uid),
            };
            msg_count += 1;
        }

        if result.is_none() {
            warn!("party [{}] keygen execution was not completed", my_uid);
            return KeygenResult::default();
        }

        info!("party [{}] keygen execution complete", my_uid);

        result.unwrap()
    }

    async fn execute_recover(
        &mut self,
        keygen_init: proto::KeygenInit,
        share_recovery_infos: Vec<Vec<u8>>,
    ) {
        let keygen_init = Some(keygen_init);
        let recover_request = proto::RecoverRequest {
            keygen_init,
            share_recovery_infos,
        };
        let response = self
            .client
            .recover(Request::new(recover_request))
            .await
            .unwrap()
            .into_inner();

        // prost way to convert i32 to enums https://github.com/danburkert/prost#enumerations
        match proto::recover_response::Response::from_i32(response.response) {
            Some(proto::recover_response::Response::Success) => {
                info!("Got success from recover")
            }
            Some(proto::recover_response::Response::Fail) => {
                warn!("Got fail from recover")
            }
            None => {
                panic!("Invalid recovery response. Could not convert i32 to enum")
            }
        }
    }

    async fn execute_sign(
        &mut self,
        init: proto::SignInit,
        channels: SenderReceiver,
        mut delivery: Deliverer,
        my_uid: &str,
    ) -> SignResult {
        let (sign_server_incoming, rx) = channels;
        let mut sign_server_outgoing = self
            .client
            .sign(Request::new(UnboundedReceiverStream::new(rx)))
            .await
            .unwrap()
            .into_inner();

        // TODO: support multiple shares for sign
        let all_share_count = init.party_uids.len();
        let my_share_count = 1;

        // the first outbound message is sign init info
        sign_server_incoming
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::SignInit(init)),
            })
            .unwrap();

        // use Option of SignResult to avoid giving a default value to SignResult
        let mut result: Option<SignResult> = None;
        let mut msg_count = 1;
        while let Some(msg) = sign_server_outgoing.message().await.unwrap() {
            let msg_type = msg.data.as_ref().expect("missing data");

            match msg_type {
                #[allow(clippy::unused)] // allow unsused traffin in non malicious
                proto::message_out::Data::Traffic(traffic) => {
                    // in malicous case, if we are stallers we skip the message
                    #[cfg(feature = "malicious")]
                    {
                        let round = sign_round(msg_count, all_share_count, my_share_count);
                        if self.malicious_data.timeout_round == round {
                            warn!("{} is stalling a message in round {}", my_uid, round - 4); // subtract keygen rounds
                            continue; // tough is the life of the staller
                        }
                        if self.malicious_data.disrupt_round == round {
                            warn!("{} is disrupting a message in round {}", my_uid, round);
                            let mut t = traffic.clone();
                            t.payload = traffic.payload[0..traffic.payload.len() / 2].to_vec();
                            let mut m = msg.clone();
                            m.data = Some(proto::message_out::Data::Traffic(t));
                            delivery.deliver(&m, &my_uid);
                        }
                    }
                    delivery.deliver(&msg, &my_uid);
                }
                proto::message_out::Data::SignResult(res) => {
                    result = Some(res.clone());
                    info!("party [{}] sign finished!", my_uid);
                    break;
                }
                proto::message_out::Data::NeedRecover(res) => {
                    info!(
                        "party [{}] needs recover for session [{}]",
                        my_uid, res.session_id
                    );
                    // when recovery is needed, sign is canceled. We abort the protocol manualy instead of waiting parties to time out
                    // no worries that we don't wait for enough time, we will not be checking criminals in this case
                    delivery.send_timeouts(0);
                    break;
                }
                _ => panic!("party [{}] sign error: bad outgoing message type", my_uid),
            };
            msg_count += 1;
        }

        // return default value for SignResult if socket closed before I received the result
        if result.is_none() {
            warn!("party [{}] sign execution was not completed", my_uid);
            return SignResult::default();
        }
        info!("party [{}] sign execution complete", my_uid);

        result.unwrap() // it's safe to unwrap here
    }

    async fn shutdown(mut self) {
        self.server_shutdown_sender.send(()).unwrap(); // tell the server to shut down
        self.server_handle.await.unwrap(); // wait for server to shut down
        info!("party [{}] shutdown success", self.server_port);
    }

    fn get_db_path(&self) -> std::path::PathBuf {
        gg20::service::tests::get_db_path(&self.db_name)
    }
}
