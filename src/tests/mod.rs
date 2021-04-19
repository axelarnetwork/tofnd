// Notes:
// # Helper functions:
// Since we are using tokio, we need to make use of async function. That comes
// with the unfortunate necessity to declare some extra functions in order to
// facilitate the tests. These functions are:
// 1. src/kv_manager::KV::get_db_paths
// 2. src/gg20/mod::get_db_paths
// 3. src/gg20/mod::with_db_name

use std::convert::TryFrom;

mod mock;
mod tofnd_party;

use crate::proto;
use mock::{Deliverer, Party};
use tofnd_party::TofndParty;

use std::path::Path;
use testdir::testdir;

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    static ref TEST_CASES: Vec<(usize, Vec<u32>, usize, Vec<usize>)> = vec![ // (number of uids, count of shares per uid, threshold, indices of sign participants)
        (5, vec![], 3, vec![1,4,2,3]),          // should initialize share_counts into [1,1,1,1,1]
        (5, vec![1,1,1,1,1], 3, vec![1,4,2,3]), // 1 share per uid
        (5, vec![1,2,1,3,2], 6, vec![1,4,2,3]), // multiple shares per uid
        (1,vec![1],0,vec![0]),                  // trivial case
        (5,vec![1,2,3,4,20],27,vec![0,1,2,3,4]), // many share counts
    ];
    // TODO add TEST_CASES_INVALID
}

#[tokio::test]
async fn basic_keygen_and_sign() {
    let dir = testdir!();

    for (uid_count, party_share_counts, threshold, sign_participant_indices) in TEST_CASES.iter() {
        let (parties, party_uids) = init_parties(*uid_count, &dir).await;

        // println!(
        //     "keygen: share_count:{}, threshold: {}",
        //     share_count, threshold
        // );
        let new_key_uid = "Gus-test-key";
        let parties = execute_keygen(
            parties,
            &party_uids,
            &party_share_counts,
            new_key_uid,
            *threshold,
        )
        .await;

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let parties = execute_sign(
            parties,
            &party_uids,
            sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
        )
        .await;

        delete_dbs(&parties);
        shutdown_parties(parties).await;
    }
}

#[tokio::test]
async fn restart_one_party() {
    let dir = testdir!();

    for (uid_count, party_share_counts, threshold, sign_participant_indices) in TEST_CASES.iter() {
        let (parties, party_uids) = init_parties(*uid_count, &dir).await;

        // println!(
        //     "keygen: share_count:{}, threshold: {}",
        //     share_count, threshold
        // );
        let new_key_uid = "Gus-test-key";
        let parties = execute_keygen(
            parties,
            &party_uids,
            &party_share_counts,
            new_key_uid,
            *threshold,
        )
        .await;

        let shutdown_index = sign_participant_indices[0];
        println!("restart party {}", shutdown_index);
        // use Option to temporarily transfer ownership of individual parties to a spawn
        let mut party_options: Vec<Option<_>> = parties.into_iter().map(Some).collect();
        let shutdown_party = party_options[shutdown_index].take().unwrap();
        shutdown_party.shutdown().await;

        party_options[shutdown_index] = Some(TofndParty::new(shutdown_index, &dir).await);
        let parties = party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>();

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let parties = execute_sign(
            parties,
            &party_uids,
            sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
        )
        .await;

        delete_dbs(&parties);
        shutdown_parties(parties).await;
    }
}

async fn init_parties(share_count: usize, testdir: &Path) -> (Vec<TofndParty>, Vec<String>) {
    let mut parties = Vec::with_capacity(share_count);

    // use a for loop because async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for i in 0..share_count {
        parties.push(TofndParty::new(i, testdir).await);
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

fn delete_dbs(parties: &[impl Party]) {
    for p in parties {
        // Sled creates a directory for the database and its configuration
        std::fs::remove_dir_all(p.get_db_path()).unwrap();
    }
}

// need to take ownership of parties `parties` and return it on completion
async fn execute_keygen(
    parties: Vec<TofndParty>,
    party_uids: &[String],
    party_share_counts: &[u32],
    new_key_uid: &str,
    threshold: usize,
) -> Vec<TofndParty> {
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
            party_share_counts: party_share_counts.to_owned(),
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
