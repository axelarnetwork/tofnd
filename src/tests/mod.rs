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

#[cfg(not(feature = "malicious"))]
mod test_cases;
#[cfg(not(feature = "malicious"))]
use test_cases::*;

#[cfg(feature = "malicious")]
mod malicious_test_cases;
#[cfg(feature = "malicious")]
use malicious_test_cases::*;

use tofn::protocol::gg20::sign::crimes::Crime;

use crate::proto::{
    self,
    message_out::{
        sign_result::SignResultData::{Criminals, Signature},
        SignResult,
    },
};
use mock::{Deliverer, Party};
use tofnd_party::TofndParty;

use std::path::Path;
use testdir::testdir;

// enable logs in tests
use tracing_test::traced_test;

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::MaliciousType::{self};

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    // (number of uids, count of shares per uid, threshold, indices of sign participants, malicious types)
    static ref TEST_CASES: Vec<TestCase> = generate_test_cases();
}

// struct to pass in init_parties function.
// needs to include malicious when we are running in malicious mode
struct InitParties {
    party_count: usize,
    #[cfg(feature = "malicious")]
    malicious_types: Vec<MaliciousType>,
}

impl InitParties {
    #[cfg(not(feature = "malicious"))]
    fn new(party_count: usize) -> InitParties {
        InitParties { party_count }
    }
    #[cfg(feature = "malicious")]
    fn new(party_count: usize, malicious_types: Vec<MaliciousType>) -> InitParties {
        InitParties {
            party_count,
            malicious_types,
        }
    }
}

fn check_results(results: Vec<SignResult>, expected_crimes: &[Vec<Crime>]) {
    // get the first non-empty result. We can't simply take results[0] because some behaviours
    // don't return results and we pad them with `None`s
    let first = results
        .iter()
        .find(|r| r.sign_result_data.is_some())
        .unwrap();
    match first.sign_result_data {
        Some(Signature(_)) => {
            assert_eq!(
                expected_crimes
                    .iter()
                    .filter(|inner_crime_list| !inner_crime_list.is_empty())
                    .count(),
                0,
                "Expected crimes but didn't discover any",
            );
            for (i, result) in results.iter().enumerate() {
                assert_eq!(
                    first, result,
                    "party {} didn't produce the expected result",
                    i
                );
            }
        }
        Some(Criminals(ref criminal_list)) => {
            // chack that we have the correct number of criminals
            let expected_criminal_count = expected_crimes
                .iter()
                .filter(|list| !list.is_empty())
                .count();
            let actual_criminal_count = criminal_list.criminals.len();
            assert_eq!(expected_criminal_count, actual_criminal_count);
            println!("criminals: {:?}", criminal_list.criminals);
        }
        None => {
            panic!("Result was None");
        }
    }
}

#[traced_test]
#[tokio::test]
async fn basic_keygen_and_sign() {
    let dir = testdir!();

    // for (uid_count, party_share_counts, threshold, sign_participant_indices, malicious_types) in
    for test_case in TEST_CASES.iter() {
        let uid_count = test_case.uid_count;
        let party_share_counts = &test_case.share_counts;
        let threshold = test_case.threshold;
        let sign_participant_indices = &test_case.signer_indices;

        // get malicious types only when we are in malicious mode
        #[cfg(feature = "malicious")]
        let malicious_types = &test_case.malicious_types;
        #[cfg(feature = "malicious")]
        let expected_crimes = &test_case.expected_crimes;
        #[cfg(feature = "malicious")]
        println!("======= Expected crimes: {:?}", expected_crimes);

        // initialize parties with malicious_types when we are in malicious mode
        #[cfg(not(feature = "malicious"))]
        let init_parties_t = InitParties::new(uid_count);
        #[cfg(feature = "malicious")]
        let init_parties_t = InitParties::new(uid_count, malicious_types.clone());

        #[cfg(not(feature = "malicious"))]
        let expect_results = vec![true; uid_count];
        #[cfg(feature = "malicious")]
        let expect_results = {
            let mut expect_results = vec![true; uid_count];
            for (i, t) in malicious_types.iter().enumerate() {
                if matches!(
                    t,
                    MaliciousType::R3BadProof
                        | MaliciousType::R4BadReveal
                        | MaliciousType::R6BadProof
                ) {
                    expect_results[i] = false;
                }
            }
            expect_results
        };

        let (parties, party_uids) = init_parties(&init_parties_t, &dir, &expect_results).await;

        // println!(
        //     "keygen: share_count:{}, threshold: {}",
        //     share_count, threshold
        // );
        let new_key_uid = "Gus-test-key";
        let parties = execute_keygen(
            parties,
            &party_uids,
            party_share_counts,
            new_key_uid,
            threshold,
        )
        .await;

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let (parties, results) = execute_sign(
            parties,
            &party_uids,
            sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
            &expect_results,
        )
        .await;

        delete_dbs(&parties);
        shutdown_parties(parties).await;

        check_results(results, &expected_crimes);
    }
}

#[traced_test]
#[tokio::test]
async fn restart_one_party() {
    let dir = testdir!();

    // for (uid_count, party_share_counts, threshold, sign_participant_indices, malicious_types) in
    for test_case in TEST_CASES.iter() {
        let uid_count = test_case.uid_count;
        let party_share_counts = &test_case.share_counts;
        let threshold = test_case.threshold;
        let sign_participant_indices = &test_case.signer_indices;

        // get malicious types only when we are in malicious mode
        #[cfg(feature = "malicious")]
        let malicious_types = &test_case.malicious_types;
        #[cfg(feature = "malicious")]
        let expected_crimes = &test_case.expected_crimes;
        #[cfg(feature = "malicious")]
        println!("======= Expected crimes: {:?}", expected_crimes);

        // initialize parties with malicious_types when we are in malicious mode
        #[cfg(not(feature = "malicious"))]
        let init_parties_t = InitParties::new(uid_count);
        #[cfg(feature = "malicious")]
        let init_parties_t = InitParties::new(uid_count, malicious_types.clone());

        #[cfg(not(feature = "malicious"))]
        let expect_results = vec![true; uid_count];
        #[cfg(feature = "malicious")]
        let expect_results = {
            let mut expect_results = vec![true; uid_count];
            for (i, t) in malicious_types.iter().enumerate() {
                if matches!(
                    t,
                    MaliciousType::R3BadProof
                        | MaliciousType::R4BadReveal
                        | MaliciousType::R6BadProof
                ) {
                    expect_results[i] = false;
                }
            }
            expect_results
        };

        let (parties, party_uids) = init_parties(&init_parties_t, &dir, &expect_results).await;

        // println!(
        //     "keygen: share_count:{}, threshold: {}",
        //     share_count, threshold
        // );
        let new_key_uid = "Gus-test-key";
        let parties = execute_keygen(
            parties,
            &party_uids,
            party_share_counts,
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

        // initialize restarted party with malicious_type when we are in malicious mode
        #[cfg(not(feature = "malicious"))]
        let init_party = InitParty::new(shutdown_index);
        #[cfg(feature = "malicious")]
        let init_party = InitParty::new(
            shutdown_index,
            malicious_types.get(shutdown_index).unwrap().clone(),
        );

        party_options[shutdown_index] =
            Some(TofndParty::new(init_party, &dir, expect_results[shutdown_index]).await);
        let parties = party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>();

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let (parties, results) = execute_sign(
            parties,
            &party_uids,
            &sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
            &expect_results,
        )
        .await;

        delete_dbs(&parties);
        shutdown_parties(parties).await;

        check_results(results, &expected_crimes);
    }
}

// struct to pass in TofndParty constructor.
// needs to include malicious when we are running in malicious mode
struct InitParty {
    party_index: usize,
    #[cfg(feature = "malicious")]
    malicious_type: MaliciousType,
}

impl InitParty {
    #[cfg(not(feature = "malicious"))]
    fn new(party_index: usize) -> InitParty {
        InitParty { party_index }
    }

    #[cfg(feature = "malicious")]
    fn new(party_index: usize, malicious_type: MaliciousType) -> InitParty {
        InitParty {
            party_index,
            malicious_type,
        }
    }
}

async fn init_parties(
    init_parties: &InitParties,
    testdir: &Path,
    expect_results: &[bool],
) -> (Vec<TofndParty>, Vec<String>) {
    let mut parties = Vec::with_capacity(init_parties.party_count);

    // use a for loop because async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for i in 0..init_parties.party_count {
        // initialize party with respect to current build
        #[cfg(not(feature = "malicious"))]
        let init_party = InitParty::new(i);
        #[cfg(feature = "malicious")]
        let init_party = InitParty::new(i, init_parties.malicious_types.get(i).unwrap().clone());
        parties.push(TofndParty::new(init_party, testdir, *expect_results.get(i).unwrap()).await);
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
    expect_results: &[bool],
) -> (Vec<impl Party>, Vec<proto::message_out::SignResult>) {
    let participant_uids: Vec<String> = sign_participant_indices
        .iter()
        .map(|&i| party_uids[i].clone())
        .collect();
    let (sign_delivery, sign_channel_pairs) = Deliverer::with_party_ids(&participant_uids);
    #[cfg(feature = "malicious")]
    let mut extra_delivery = sign_delivery.clone();

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
            let result = party
                .execute_sign(init, channel_pair, delivery, &participant_uid)
                .await;
            (party, result)
        });
        sign_join_handles.push((participant_index, handle));
    }

    let mut results = vec![SignResult::default(); sign_join_handles.len()];
    #[cfg(feature = "malicious")]
    let mut blocked_parties = Vec::new();
    for (i, h) in sign_join_handles {
        // if handle belongs to a party that we don't expect to return a result,
        // don't wait for it and don't retrieve its result either
        #[cfg(feature = "malicious")]
        if !expect_results[i] {
            println!("Party {} is blocked :(", i);
            blocked_parties.push((i, h));
            continue;
        }
        let handle = h.await.unwrap();
        party_options[i] = Some(handle.0);
        results[i] = handle.1;
    }

    #[cfg(feature = "malicious")]
    for (party_index, handle) in blocked_parties {
        // create and send dummy data to unblock any blocked parties
        let dummy_data = proto::message_out::Data::Traffic(proto::TrafficOut {
            to_party_uid: "blocked".to_string(),
            payload: Vec::<u8>::with_capacity(1),
            is_broadcast: true,
        });
        extra_delivery
            .deliver(
                &proto::MessageOut {
                    data: Some(dummy_data),
                },
                "ghost",
            )
            .await;
        let handle = handle.await.unwrap();
        party_options[party_index] = Some(handle.0);
        results[party_index] = handle.1;
        println!("Party {} is unblocked :)", party_index);
    }
    (
        party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>(),
        results,
    )
}
