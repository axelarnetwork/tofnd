// Notes:
// # Helper functions:
// Since we are using tokio, we need to make use of async function. That comes
// with the unfortunate necessity to declare some extra functions in order to
// facilitate the tests. These functions are:
// 1. src/kv_manager::KV::get_db_paths
// 2. src/gg20/mod::get_db_paths
// 3. src/gg20/mod::with_db_name

use std::convert::TryFrom;
use std::path::Path;
use testdir::testdir;

mod mock;
mod tofnd_party;

mod honest_test_cases;

#[cfg(feature = "malicious")]
mod malicious_test_cases;
#[cfg(feature = "malicious")]
use malicious_test_cases::*;

use tofn::protocol::gg20::sign::crimes::Crime;
use tracing::info;

use crate::proto::{
    self,
    message_out::{
        sign_result::SignResultData::{Criminals, Signature},
        SignResult,
    },
};
use mock::{Deliverer, Party};
use tofnd_party::TofndParty;

use crate::gg20::proto_helpers::to_criminals;

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::MaliciousType;

struct TestCase {
    uid_count: usize,
    share_counts: Vec<u32>,
    threshold: usize,
    signer_indices: Vec<usize>,
    expected_crimes: Vec<Vec<Crime>>,
    #[cfg(feature = "malicious")]
    malicious_data: MaliciousData,
}

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];

}

// struct to pass in init_parties function.
// needs to include malicious when we are running in malicious mode
struct InitParties {
    party_count: usize,
    #[cfg(feature = "malicious")]
    malicious_data: MaliciousData,
}

impl InitParties {
    #[cfg(not(feature = "malicious"))]
    fn new(party_count: usize) -> InitParties {
        InitParties { party_count }
    }
    #[cfg(feature = "malicious")]
    fn new(party_count: usize, malicious_data: &MaliciousData) -> InitParties {
        InitParties {
            party_count,
            malicious_data: malicious_data.clone(),
        }
    }
}

async fn run_test_cases(test_cases: &[TestCase], restart: bool) {
    let dir = testdir!();
    for test_case in test_cases {
        basic_keygen_and_sign(test_case, &dir, restart).await;
    }
}

fn check_results(results: Vec<SignResult>, expected_crimes: &[Vec<Crime>]) {
    // get the first non-empty result. We can't simply take results[0] because some behaviours
    // don't return results and we pad them with `None`s
    let first = results.iter().find(|r| r.sign_result_data.is_some());

    // else we have at least one result
    let first = first.unwrap();
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
        Some(Criminals(ref actual_criminals)) => {
            // Check that we got all criminals
            // that's a temporary hack, but will be soon replaced after result
            // type is replaced with Vec<Vec<Crimes>>; then, we will simple do
            // assert_eq(expected_crimes, actual_crimes);
            // When this happens, also remove pub from mod gg20::proto_helpers
            // because we no longer need to use to_crimes
            let expected_criminals = to_criminals(expected_crimes);
            for (actual_criminal, expected_criminal) in actual_criminals
                .criminals
                .iter()
                .zip(expected_criminals.iter())
            {
                // use the convention that party names are constructed from ints converted to chars.
                let criminal_index =
                    actual_criminal.party_uid.chars().next().unwrap() as usize - 'A' as usize;
                assert_eq!(expected_criminal.index, criminal_index);
            }
            println!("criminals: {:?}", actual_criminals.criminals);
        }
        None => {
            panic!("Result was None");
        }
    }
}

// async fn restart_one_party(test_case: &TestCase, dir: &Path, restart: bool) {
async fn basic_keygen_and_sign(test_case: &TestCase, dir: &Path, restart: bool) {
    let uid_count = test_case.uid_count;
    let party_share_counts = &test_case.share_counts;
    let threshold = test_case.threshold;
    let sign_participant_indices = &test_case.signer_indices;
    let expected_crimes = &test_case.expected_crimes;

    info!("======= Expected crimes: {:?}", expected_crimes);

    #[cfg(not(feature = "malicious"))]
    let init_parties_t = InitParties::new(uid_count);
    #[cfg(feature = "malicious")]
    let init_parties_t = InitParties::new(uid_count, &test_case.malicious_data);

    let (parties, party_uids) = init_parties(&init_parties_t, &dir).await;

    // println!(
    //     "keygen: share_count:{}, threshold: {}",
    //     share_count, threshold
    // );
    let new_key_uid = "Gus-test-key";
    let mut parties = execute_keygen(
        parties,
        &party_uids,
        party_share_counts,
        new_key_uid,
        threshold,
    )
    .await;

    if restart {
        let shutdown_index = sign_participant_indices[0];
        println!("restart party {}", shutdown_index);
        // use Option to temporarily transfer ownership of individual parties to a spawn
        let mut party_options: Vec<Option<_>> = parties.into_iter().map(Some).collect();
        let shutdown_party = party_options[shutdown_index].take().unwrap();
        shutdown_party.shutdown().await;

        // initialize restarted party with malicious_type when we are in malicious mode
        let init_party = InitParty::new(
            shutdown_index,
            #[cfg(feature = "malicious")]
            &test_case.malicious_data,
        );
        party_options[shutdown_index] = Some(TofndParty::new(init_party, &dir).await);

        parties = party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>();
    }

    // println!("sign: participants {:?}", sign_participant_indices);
    let new_sig_uid = "Gus-test-sig";
    let (parties, results) = execute_sign(
        parties,
        &party_uids,
        sign_participant_indices,
        new_key_uid,
        new_sig_uid,
        &MSG_TO_SIGN,
        #[cfg(not(feature = "malicious"))]
        false,
        #[cfg(feature = "malicious")]
        test_case.malicious_data.timeout.is_some(),
    )
    .await;

    delete_dbs(&parties);
    shutdown_parties(parties).await;

    check_results(results, &expected_crimes);
}

#[cfg(feature = "malicious")]
#[derive(Clone, Debug)]
struct PartyMaliciousData {
    timeout: Option<Timeout>,
    spoof: Option<Spoof>,
    malicious_type: MaliciousType,
}

// struct to pass in TofndParty constructor.
// needs to include malicious when we are running in malicious mode
struct InitParty {
    party_index: usize,
    #[cfg(feature = "malicious")]
    malicious_data: PartyMaliciousData,
}

impl InitParty {
    #[cfg(not(feature = "malicious"))]
    fn new(my_index: usize) -> InitParty {
        InitParty {
            party_index: my_index,
        }
    }
    #[cfg(feature = "malicious")]
    fn new(my_index: usize, all_malicious_data: &MaliciousData) -> InitParty {
        let mut my_timeout = None;
        if let Some(timeout) = all_malicious_data.timeout.clone() {
            if timeout.index == my_index {
                my_timeout = Some(timeout);
            }
        }

        let mut my_spoof = None;
        if let Some(spoof) = all_malicious_data.spoof.clone() {
            if spoof.index == my_index {
                my_spoof = Some(spoof);
            }
        }

        let my_malicious_type = all_malicious_data
            .malicious_types
            .get(my_index)
            .unwrap()
            .clone();

        let my_malicious_data = PartyMaliciousData {
            timeout: my_timeout,
            spoof: my_spoof,
            malicious_type: my_malicious_type,
        };

        InitParty {
            party_index: my_index,
            malicious_data: my_malicious_data,
        }
    }
}

async fn init_parties(
    init_parties: &InitParties,
    testdir: &Path,
) -> (Vec<TofndParty>, Vec<String>) {
    let mut parties = Vec::with_capacity(init_parties.party_count);

    // use a for loop because async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for i in 0..init_parties.party_count {
        #[cfg(not(feature = "malicious"))]
        let init_party = InitParty::new(i);
        #[cfg(feature = "malicious")]
        let init_party = InitParty::new(i, &init_parties.malicious_data);
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
    expect_timeout: bool,
) -> (Vec<impl Party>, Vec<proto::message_out::SignResult>) {
    println!("Expecting timeout: [{}]", expect_timeout);
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
            let result = party
                .execute_sign(init, channel_pair, delivery, &participant_uid)
                .await;
            (party, result)
        });
        sign_join_handles.push((i, handle));
    }

    #[cfg(feature = "malicious")]
    {
        // if we are expecting a timeout, abort parties after a reasonable amount of time
        if expect_timeout {
            let unblocker = sign_delivery.clone();
            abort_parties(unblocker, 10);
        }
    }

    let mut results = vec![SignResult::default(); sign_join_handles.len()];
    for (i, h) in sign_join_handles {
        println!("Running party {}", i);
        let handle = h.await.unwrap();
        party_options[sign_participant_indices[i]] = Some(handle.0);
        results[i] = handle.1;
    }
    (
        party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>(),
        results,
    )
}

#[cfg(feature = "malicious")]
fn abort_parties(mut unblocker: Deliverer, time: u64) {
    // send an abort message if protocol is taking too much time
    info!("I will send an abort message in {} seconds", time);
    std::thread::spawn(move || {
        unblocker.send_timeouts(time);
    });
    println!("Continue for now");
}
