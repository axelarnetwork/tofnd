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

// enable logs in tests
use tracing_test::traced_test;

#[cfg(not(feature = "malicious"))]
type TestCase = (usize, Vec<u32>, usize, Vec<usize>);

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};
#[cfg(feature = "malicious")]
type TestCase = (usize, Vec<u32>, usize, Vec<usize>, Vec<MaliciousType>);

#[cfg(not(feature = "malicious"))]
lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    // (number of uids, count of shares per uid, threshold, indices of sign participants, malicious types)
    static ref TEST_CASES: Vec<TestCase> = vec![
        (4, vec![], 0, vec![0,1,2,3]),              // should initialize share_counts into [1,1,1,1,1]
        (5, vec![1,1,1,1,1], 3, vec![1,4,2,3]),     // 1 share per uid
        (5, vec![1,2,1,3,2], 6, vec![1,4,2,3]),     // multiple shares per uid
        (1, vec![1], 0, vec![0]),                   // trivial case
        (5, vec![1,2,3,4,20], 27, vec![0, 1, 4, 3, 2]), // Create a malicious party
    ];
}

#[cfg(feature = "malicious")]
lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    // (number of uids, count of shares per uid, threshold, indices of sign participants, malicious types)
    static ref TEST_CASES: Vec<TestCase> = vec![
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest; 5]),    // only honest
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R1BadProof{victim:0}]),  // R1BadProof
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R1FalseAccusation{victim:0}]),  // R1FalseAccusation
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2BadMta{victim:0}]),  // R2BadMta
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2BadMtaWc{victim:0}]),  // R2BadMtaWc
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2FalseAccusationMta{victim:0}]),  // R2FalseAccusationMta
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2FalseAccusationMtaWc{victim:0}]),  // R2FalseAccusationMtaWc
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R3BadProof]),  // R3BadProof
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R3FalseAccusation{victim:0}]),  // R3FalseAccusation
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R4BadReveal]),  // R4BadReveal
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R4FalseAccusation{victim:0}]),  // R4FalseAccusation
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R5BadProof{victim:0}]),  // R5BadProof
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R5FalseAccusation{victim:0}]),  // R5FalseAccusation
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R6BadProof]),  // R6BadProof
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R6FalseAccusation{victim:0}]),  // R6FalseAccusation
        (5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R7BadSigSummand]),  // R7BadSigSummand
    ];
}

struct InitParties {
    party_count: usize,
    #[cfg(feature = "malicious")]
    malicious_types: Vec<MaliciousType>,
}

impl InitParties {
    fn new(party_count: usize) -> InitParties {
        InitParties { party_count }
    }
}

#[traced_test]
#[tokio::test]
async fn basic_keygen_and_sign() {
    let dir = testdir!();

    // for (uid_count, party_share_counts, threshold, sign_participant_indices, malicious_types) in
    for test_case in TEST_CASES.iter() {
        let uid_count = test_case.0;
        let party_share_counts = test_case.1.clone();
        let threshold = test_case.2;
        let sign_participant_indices = test_case.3.clone();

        #[cfg(feature = "malicious")]
        let malicious_types = match malicious_types.len() {
            0 => vec![Honest; *uid_count],
            _ => malicious_types.clone(),
        };

        let init_parties_t = InitParties::new(uid_count);

        let (parties, party_uids) = init_parties(&init_parties_t, &dir).await;

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
            threshold,
        )
        .await;

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let parties = execute_sign(
            parties,
            &party_uids,
            &sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
        )
        .await;

        delete_dbs(&parties);
        shutdown_parties(parties).await;
    }
}

#[traced_test]
#[tokio::test]
async fn restart_one_party() {
    let dir = testdir!();

    // for (uid_count, party_share_counts, threshold, sign_participant_indices, malicious_types) in
    for test_case in TEST_CASES.iter() {
        let uid_count = test_case.0;
        let party_share_counts = test_case.1.clone();
        let threshold = test_case.2;
        let sign_participant_indices = test_case.3.clone();

        #[cfg(feature = "malicious")]
        let malicious_types = match malicious_types.len() {
            0 => vec![Honest; *uid_count],
            _ => malicious_types.clone(),
        };
        let init_parties_t = InitParties::new(uid_count);
        let (parties, party_uids) = init_parties(&init_parties_t, &dir).await;

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
            threshold,
        )
        .await;

        let shutdown_index = sign_participant_indices[0];
        println!("restart party {}", shutdown_index);
        // use Option to temporarily transfer ownership of individual parties to a spawn
        let mut party_options: Vec<Option<_>> = parties.into_iter().map(Some).collect();
        let shutdown_party = party_options[shutdown_index].take().unwrap();
        shutdown_party.shutdown().await;

        let init_party = InitParty::new(shutdown_index);

        party_options[shutdown_index] = Some(TofndParty::new(init_party, &dir).await);
        let parties = party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>();

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let parties = execute_sign(
            parties,
            &party_uids,
            &sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
        )
        .await;

        delete_dbs(&parties);
        shutdown_parties(parties).await;
    }
}

struct InitParty {
    party_index: usize,
    #[cfg(feature = "malicious")]
    malicious_type: Vec<MaliciousType>,
}

impl InitParty {
    fn new(party_index: usize) -> InitParty {
        InitParty { party_index }
    }
}

async fn init_parties(
    init_parties: &InitParties,
    testdir: &Path,
) -> (Vec<TofndParty>, Vec<String>) {
    let mut parties = Vec::with_capacity(init_parties.party_count);

    // use a for loop because async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for i in 0..init_parties.party_count {
        let init_party = InitParty::new(i);
        parties.push(TofndParty::new(init_party, testdir).await);
    }

    let party_uids: Vec<String> = (0..init_parties.party_count)
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
