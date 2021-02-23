use super::*;

use std::collections::HashMap;
use std::convert::TryFrom;
use tokio::sync::mpsc::{channel, Receiver, Sender};

mod tofnd_party;

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    static ref TEST_CASES: Vec<(usize, usize, Vec<usize>)> = vec![ // (share_count, threshold, participant_indices)
        (5, 2, vec![1,4,2,3]),
        (1,0,vec![0]),
    ];
    // TODO add TEST_CASES_INVALID
}

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
        my_uid: &str,
    );
    async fn shutdown(mut self);
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
    for (share_count, threshold, sign_participant_indices) in TEST_CASES.iter() {
        execute_keygen_and_sign(
            *share_count,
            *threshold,
            sign_participant_indices,
            &MSG_TO_SIGN,
        )
        .await;
    }
}

async fn init_parties(share_count: usize) -> (Vec<impl Party>, Vec<String>) {
    let mut parties = Vec::with_capacity(share_count);

    // use a for loop because async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for _ in 0..share_count {
        parties.push(tofnd_party::new().await);
    }

    let party_uids: Vec<String> = (0..share_count)
        .map(|i| format!("{}", (b'A' + i as u8) as char))
        .collect();
    (parties, party_uids)
}

async fn shutdown_parties(parties: Vec<impl Party>) {
    for p in parties {
        p.shutdown().await;
    }
}

// need to take ownership of parties `parties` and return it on completion
async fn execute_keygen(
    parties: Vec<impl Party + 'static>,
    party_uids: &[String],
    new_key_uid: &str,
    threshold: usize,
) -> Vec<impl Party> {
    let share_count = parties.len();
    let (keygen_delivery, keygen_channel_pairs) = Deliverer::with_party_ids(&party_uids);
    let mut keygen_join_handles = Vec::with_capacity(share_count);
    for (i, (mut party, channel_pair)) in parties
        .into_iter()
        .zip(keygen_channel_pairs.into_iter())
        .enumerate()
    {
        let init = proto::KeygenInit {
            new_key_uid: new_key_uid.to_string(),
            party_uids: party_uids.to_owned(),
            my_party_index: i32::try_from(i).unwrap(),
            threshold: i32::try_from(threshold).unwrap(),
        };
        let delivery = keygen_delivery.clone();
        let handle = tokio::spawn(async move {
            party.execute_keygen(init, channel_pair, delivery).await;
            party
        });
        keygen_join_handles.push(handle);
    }
    let mut parties = Vec::with_capacity(share_count); // async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for h in keygen_join_handles {
        parties.push(h.await.unwrap());
    }
    parties
}

// need to take ownership of parties `parties` and return it on completion
async fn execute_sign(
    parties: Vec<impl Party + 'static>,
    party_uids: &[String],
    sign_participant_indices: &[usize],
    key_uid: &str,
    new_sig_uid: &str,
    msg_to_sign: &[u8],
) -> Vec<impl Party> {
    let participant_uids: Vec<String> = sign_participant_indices
        .iter()
        .map(|&i| party_uids[i].clone())
        .collect();
    let (sign_delivery, sign_channel_pairs) = Deliverer::with_party_ids(&participant_uids);

    // use Option to temporarily transfer ownership of individual parties to a spawn
    let mut party_options: Vec<Option<_>> = parties.into_iter().map(Some).collect();

    let mut sign_join_handles = Vec::with_capacity(sign_participant_indices.len());
    for (i, channel_pair) in sign_channel_pairs.into_iter().enumerate() {
        let participant_index = sign_participant_indices[i];

        // clone everything needed in spawn
        let init = proto::SignInit {
            new_sig_uid: new_sig_uid.to_string(),
            key_uid: key_uid.to_string(),
            party_uids: participant_uids.clone(),
            message_to_sign: msg_to_sign.to_vec(),
        };
        let delivery = sign_delivery.clone();
        let participant_uid = participant_uids[i].clone();
        let mut party = party_options[participant_index].take().unwrap();

        // execute the protocol in a spawn
        let handle = tokio::spawn(async move {
            party
                .execute_sign(init, channel_pair, delivery, &participant_uid)
                .await;
            party
        });
        sign_join_handles.push((participant_index, handle));
    }

    // move participants back into party_options
    for (i, h) in sign_join_handles {
        party_options[i] = Some(h.await.unwrap());
    }
    party_options
        .into_iter()
        .map(|o| o.unwrap())
        .collect::<Vec<_>>()
}

async fn execute_keygen_and_sign(
    share_count: usize,
    threshold: usize,
    sign_participant_indices: &[usize],
    msg_to_sign: &[u8],
) {
    println!(
        "keygen and sign test: share_count: {}, threshold: {}, sign_participants {:?}",
        share_count, threshold, sign_participant_indices
    );

    let (parties, party_uids) = init_parties(share_count).await;

    // run keygen protocol
    let new_key_uid = "Gus-test-key";
    let parties = execute_keygen(parties, &party_uids, new_key_uid, threshold).await;

    // run sign protocol
    let new_sig_uid = "Gus-test-sig";
    let parties = execute_sign(
        parties,
        &party_uids,
        sign_participant_indices,
        new_key_uid,
        new_sig_uid,
        msg_to_sign,
    )
    .await;

    shutdown_parties(parties).await;
}
