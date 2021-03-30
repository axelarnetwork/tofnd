use tofn::protocol::gg20::keygen::{CommonInfo, SecretKeyShare, ShareInfo};

use self::keygen::{get_party_info, route_messages};
use self::protocol::map_tofnd_to_tofn_idx;

use super::proto;
use crate::{kv_manager::Kv, TofndError};

// tonic cruft
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub common: CommonInfo,
    pub shares: Vec<ShareInfo>,
}
// use std::pin::Pin;
// use futures_core::Stream;
// use futures_util::StreamExt;

// TODO don't store party_uids in this daemon!
type KeySharesKv = Kv<PartyInfo>;

struct Gg20Service {
    kv: KeySharesKv,
}

use tofn::protocol::gg20::keygen::ECPoint;

pub fn new_service() -> impl proto::gg20_server::Gg20 {
    Gg20Service {
        kv: KeySharesKv::new(),
    }
}

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for Gg20Service {
    // type KeygenStream = Pin<Box<dyn Stream<Item = Result<proto::MessageOut, Status>> + Send + Sync + 'static>>;
    type KeygenStream = mpsc::Receiver<Result<proto::MessageOut, Status>>;
    type SignStream = Self::KeygenStream;

    // TODO delete get_key, get_sign?
    async fn get_key(
        &self,
        request: Request<proto::Uid>,
    ) -> Result<Response<proto::Bytes>, Status> {
        println!("get_key uid {:?}", request.get_ref());
        Ok(Response::new(proto::Bytes {
            payload: vec![1, 2, 3],
        }))
    }

    async fn get_sig(
        &self,
        request: Request<proto::Uid>,
    ) -> Result<Response<proto::Bytes>, Status> {
        println!("get_sig uid {:?}", request.get_ref());
        Ok(Response::new(proto::Bytes {
            payload: vec![3, 2, 1],
        }))
    }

    async fn keygen(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let mut stream_in = request.into_inner();
        let (mut stream_out_sender, stream_out_reader) = mpsc::channel(4);

        let mut kv = self.kv.clone();

        // spawn a master thread to immediately return from gRPC
        // Inside this master thread, we do the following:
        // 1. Receive KeygenInit, open message, sanitize arguments
        // 2. Reserve the key in kv store
        // 3. Spawn N keygen threads to execute the protocol in parallel; one of each of our shares to
        // 4. Spawn 1 router thread to route messages from axelar core to the respective keygen thread
        // 5. Wait for all keygen threads to finish and aggregate all SecretKeyShares
        // 6. Create a struct that contains all common and share-spacific information for out party and add it into the KV store
        tokio::spawn(async move {
            // get KeygenInit message from stream
            let keygen_init = match keygen::handle_keygen_init(&mut stream_in).await {
                Ok(k) => k,
                Err(e) => {
                    println!("Keygen: Init: {:?}", e);
                    return;
                }
            };

            // reserve key
            let key_uid_reservation = kv
                .reserve_key(keygen_init.new_key_uid.clone())
                .await
                .unwrap();

            // find my share count
            let my_share_count = keygen_init.my_shares_count();

            // create in and out channels for each share, and spawn as many threads
            let mut keygen_senders = Vec::new();
            let mut aggregator_receivers = Vec::new();
            let my_starting_tofn_index =
                map_tofnd_to_tofn_idx(keygen_init.my_index, 0, &keygen_init.party_share_counts);

            for my_tofnd_subindex in 0..my_share_count {
                let (keygen_sender, keygen_receiver) = mpsc::channel(4);
                let (aggregator_sender, aggregator_receiver) = oneshot::channel();
                keygen_senders.push(keygen_sender);
                aggregator_receivers.push(aggregator_receiver);

                // make copies to pass to execute keygen thread
                let stream_out = stream_out_sender.clone();
                let uids = keygen_init.party_uids.clone();
                let shares = keygen_init.party_share_counts.clone();
                let threshold = keygen_init.threshold;
                let my_tofn_index = my_starting_tofn_index + my_tofnd_subindex;
                tokio::spawn(async move {
                    // get result of keygen
                    let secret_key_share = keygen::execute_keygen(
                        keygen_receiver,
                        stream_out,
                        &uids,
                        &shares,
                        threshold,
                        my_tofn_index,
                        "log:".to_owned(),
                    )
                    .await;
                    let _ = aggregator_sender.send(secret_key_share);
                    return;
                });
            }

            // spawn a router thread
            tokio::spawn(async move {
                if let Err(e) = route_messages(&mut stream_in, keygen_senders).await {
                    println!("Error at Keygen message router: {}", e);
                }
                return;
            });

            //  wait all keygen threads and aggregare secret key shares
            let secret_key_shares =
                match keygen::aggregate_secret_key_shares(aggregator_receivers, my_share_count)
                    .await
                {
                    Err(e) => {
                        println!(
                            "Error at Keygen secret key aggregation. Unreserving key: {}",
                            e
                        );
                        kv.unreserve_key(key_uid_reservation).await;
                        return;
                    }
                    Ok(secret_key_shares) => secret_key_shares,
                };
            // TODO: gather all secret key shares and add to kv store
            // for secret_key_share in secret_key_shares {
            let secret_key_share = secret_key_shares[0].clone().unwrap();
            let pubkey = secret_key_share.ecdsa_public_key.get_element().serialize(); // bitcoin-style serialization

            // compine all keygen threads responses to a single struct
            let kv_data = get_party_info(secret_key_shares, keygen_init.party_uids);
            if kv_data.is_err() {
                println!("Error at combing kv data: {:?}", kv_data.err());
                return;
            }
            let kv_data = kv_data.unwrap();

            // try to put data inside kv store
            if let Err(e) = kv.put(key_uid_reservation, kv_data).await {
                println!("Error at inserting secret key in KV: {}", e);
                return;
            }

            // serialize generated public key and send to client
            if let Err(e) = stream_out_sender
                .send(Ok(proto::MessageOut::new_keygen_result(&pubkey)))
                .await
            {
                println!("Error at sending Public Key to stream: {}", e);
                return;
            }
            return;
        });

        Ok(Response::new(stream_out_reader))
    }

    async fn sign(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let mut stream = request.into_inner();
        let (msg_sender, rx) = mpsc::channel(4);
        let kv = self.kv.clone();

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = sign::execute_sign(&mut stream, msg_sender, kv).await {
                println!("sign failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(rx))
    }
}

mod keygen;
mod protocol;
mod sign;

// convenience constructors
impl proto::MessageOut {
    fn new_bcast(bcast: &[u8]) -> Self {
        Self::new_traffic("", bcast, true)
    }
    fn new_p2p(receiver_id: &str, p2p: &[u8]) -> Self {
        Self::new_traffic(receiver_id, p2p, false)
    }
    fn new_traffic(receiver_id: &str, msg: &[u8], is_broadcast: bool) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::Traffic(proto::TrafficOut {
                to_party_uid: receiver_id.to_string(),
                payload: msg.to_vec(),
                is_broadcast,
            })),
        }
    }
    fn new_keygen_result(result: &[u8]) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::KeygenResult(result.to_vec())),
        }
    }
    fn new_sign_result(result: &[u8]) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::SignResult(result.to_vec())),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{Gg20Service, KeySharesKv};
    use crate::proto;

    #[cfg(test)]
    pub fn with_db_name(db_name: &str) -> impl proto::gg20_server::Gg20 {
        Gg20Service {
            kv: KeySharesKv::with_db_name(db_name),
        }
    }

    #[cfg(test)]
    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        KeySharesKv::get_db_path(name)
    }
}
