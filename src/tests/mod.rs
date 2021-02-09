use super::*;

use std::collections::HashMap;
use std::convert::TryFrom;
use tokio::sync::mpsc::{channel, Receiver, Sender};

mod tofnd_party;

#[tonic::async_trait]
trait Party: Sync + Send {
    async fn execute_keygen(
        &mut self,
        init: proto::KeygenInit,
        channels: SenderReceiver,
        delivery: Deliverer,
    );
    async fn execute_sign(
        &mut self,
        init: proto::SignInit,
        channels: SenderReceiver,
        delivery: Deliverer,
    );
    async fn close(mut self);
}

type SenderReceiver = (Sender<proto::MessageIn>, Receiver<proto::MessageIn>);
#[derive(Clone)]
struct Deliverer {
    senders: HashMap<String, Sender<proto::MessageIn>>, // (party_uid, sender)
}
impl Deliverer {
    // fn new(party_count: usize) -> (Self, Vec<SenderReceiver>) {
    //     Self::with_party_ids(
    //         &(0..party_count)
    //             .map(|i| format!("{}", (b'A' + i as u8) as char))
    //             .collect::<Vec<String>>(),
    //     )
    // }
    fn with_party_ids(party_ids: &[String]) -> (Self, Vec<SenderReceiver>) {
        let channels: Vec<SenderReceiver> = (0..party_ids.len()).map(|_| channel(4)).collect();
        let senders = party_ids
            .iter()
            .cloned()
            .zip(channels.iter().map(|(tx, _)| tx.clone()))
            .collect();
        (Deliverer { senders }, channels)
    }
    pub async fn deliver(&mut self, msg: &proto::MessageOut, from: &str) {
        let msg = msg.data.as_ref().expect("missing data");
        let msg = match msg {
            proto::message_out::Data::Traffic(t) => t,
            _ => {
                panic!("msg must be traffic out");
            }
        };
        println!(
            "deliver from [{}] to [{}] broadcast? [{}]",
            from, msg.to_party_uid, msg.is_broadcast,
        );

        // simulate wire transmission: translate proto::MessageOut to proto::MessageIn
        let msg_in = proto::MessageIn {
            data: Some(proto::message_in::Data::Traffic(proto::TrafficIn {
                from_party_uid: from.to_string(),
                is_broadcast: msg.is_broadcast,
                payload: msg.payload.clone(),
            })),
        };

        // p2p message
        if !msg.is_broadcast {
            self.senders
                .get_mut(&msg.to_party_uid)
                .unwrap()
                .send(msg_in)
                .await
                .unwrap();
            return;
        }

        // broadcast message
        for (id, sender) in self.senders.iter_mut() {
            if id == from {
                continue; // don't broadcast to myself
            }
            sender.send(msg_in.clone()).await.unwrap();
        }
    }
}

// #[test]
#[tokio::test]
async fn keygen_and_sign() {
    let (share_count, threshold) = (5, 2);

    // init parties
    // use a for loop because async closures are unstable: https://github.com/rust-lang/rust/issues/62290
    let mut parties = Vec::with_capacity(share_count);
    for _ in 0..share_count {
        parties.push(tofnd_party::new().await);
    }

    // init party uids
    let party_uids: Vec<String> = (0..share_count)
        .map(|i| format!("{}", (b'A' + i as u8) as char))
        .collect();

    // run keygen protocol
    let new_key_uid = "Gus-test-key".to_string();
    let (keygen_delivery, keygen_channel_pairs) = Deliverer::with_party_ids(&party_uids);
    let mut keygen_join_handles = Vec::with_capacity(share_count);
    for (i, (mut party, channel_pair)) in parties
        .into_iter()
        .zip(keygen_channel_pairs.into_iter())
        .enumerate()
    {
        let init = proto::KeygenInit {
            new_key_uid: new_key_uid.clone(),
            party_uids: party_uids.clone(),
            my_party_index: i32::try_from(i).unwrap(),
            threshold,
        };
        let delivery = keygen_delivery.clone();
        let handle = tokio::spawn(async move {
            party.execute_keygen(init, channel_pair, delivery).await;
            party
        });
        keygen_join_handles.push(handle);
    }
    let mut parties = Vec::with_capacity(share_count); // async closures are unstable: https://github.com/rust-lang/rust/issues/62290
    for h in keygen_join_handles {
        parties.push(h.await.unwrap());
    }

    // run sign protocol
    // let new_sig_uid = "Gus-test-sig".to_string();
    // let (sign_delivery, sign_channel_pairs) = Deliverer::with_party_ids(&party_uids);
    // let mut sign_join_handles = Vec::with_capacity(share_count);

    // shut down servers
    for p in parties {
        p.close().await;
    }
}
