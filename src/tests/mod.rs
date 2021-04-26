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
use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};

struct TestCase {
    uid_count: usize,
    share_counts: Vec<u32>,
    threshold: usize,
    signer_indices: Vec<usize>,
    criminal_list: Vec<usize>,
    #[cfg(feature = "malicious")]
    malicious_types: Vec<MaliciousType>,
}

impl TestCase {
    #[cfg(not(feature = "malicious"))]
    fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        signer_indices: Vec<usize>,
    ) -> TestCase {
        let criminal_list = vec![];
        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            criminal_list,
        }
    }

    #[cfg(feature = "malicious")]
    fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        signer_indices: Vec<usize>,
        malicious_types: Vec<MaliciousType>,
    ) -> TestCase {
        let mut criminal_list = Vec::new();
        for (i, m) in malicious_types.iter().enumerate() {
            if !matches!(m, Honest) {
                criminal_list.push(i);
            }
        }
        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            criminal_list,
            malicious_types,
        }
    }
}

#[cfg(not(feature = "malicious"))]
lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    // (number of uids, count of shares per uid, threshold, indices of sign participants)
    static ref TEST_CASES: Vec<TestCase> = vec![
        TestCase::new(4, vec![], 0, vec![0,1,2,3]),              // should initialize share_counts into [1,1,1,1,1]
        TestCase::new(5, vec![1,1,1,1,1], 3, vec![1,4,2,3]),     // 1 share per uid
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![1,4,2,3]),     // multiple shares per uid
        TestCase::new(1, vec![1], 0, vec![0]),                   // trivial case
        // TestCase::new(5, vec![1,2,3,4,20], 27, vec![0, 1, 4, 3, 2]), // Create a malicious party
    ];
}

#[cfg(feature = "malicious")]
lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42];
    // (number of uids, count of shares per uid, threshold, indices of sign participants, malicious types)
    static ref TEST_CASES: Vec<TestCase> = vec![
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest; 5]),    // only honest
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R1BadProof{victim:0}]),  // R1BadProof
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R1FalseAccusation{victim:0}]),  // R1FalseAccusation
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2BadMta{victim:0}]),  // R2BadMta
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2BadMtaWc{victim:0}]),  // R2BadMtaWc
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2FalseAccusationMta{victim:0}]),  // R2FalseAccusationMta
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R2FalseAccusationMtaWc{victim:0}]),  // R2FalseAccusationMtaWc
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R3BadProof]),  // R3BadProof
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R3FalseAccusation{victim:0}]),  // R3FalseAccusation
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R4BadReveal]),  // R4BadReveal
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R4FalseAccusation{victim:0}]),  // R4FalseAccusation
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R5BadProof{victim:0}]),  // R5BadProof
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R5FalseAccusation{victim:0}]),  // R5FalseAccusation
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R6BadProof]),  // R6BadProof
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R6FalseAccusation{victim:0}]),  // R6FalseAccusation
        TestCase::new(5, vec![1,2,1,3,2], 6, vec![0,1,2,3,4], vec![Honest, Honest, Honest, Honest, R7BadSigSummand]),  // R7BadSigSummand
        // TODO add more complex tests for malicious behaviours
    ];
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

fn check_results(results: Vec<SignResult>, sign_indices: &[usize], expected_criminals: &[usize]) {
    assert_eq!(sign_indices.len(), results.len());
    let first = &results[sign_indices[0]];

    // if no criminals were defined, check that all parties produced the same output
    if let Some(Signature(_)) = first.sign_result_data {
        assert_eq!(
            expected_criminals.len(),
            0,
            "Expected criminals but didn't discover any",
        );
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                first, result,
                "party {} didn't produce the expected result",
                i
            );
        }
    }

    // if criminals were defined, check that all parties found all of them
    if let Some(Criminals(criminal_list)) = first.sign_result_data.clone() {
        // get criminal list
        let mut criminals = criminal_list.criminals;
        // remove duplicates
        criminals.dedup();
        // check that we are left with as many criminals as expected
        assert!(criminals.len() == expected_criminals.len());
        // check that every criminal was in the "expected" list
        for res in criminals.iter().zip(expected_criminals).into_iter() {
            let criminal_uid = format!("{}", (b'A' + *res.1 as u8) as char);
            assert_eq!(res.0.party_uid, criminal_uid);
        }
        // println!("criminals: {:?}", criminals);
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
        let expected_criminals = &test_case.criminal_list;

        // get malicious types only when we are in malicious mode
        #[cfg(feature = "malicious")]
        let malicious_types = {
            let malicious_types = test_case.malicious_types.clone();
            match malicious_types.len() {
                0 => vec![Honest; uid_count],
                _ => malicious_types,
            }
        };

        // initialize parties with malicious_types when we are in malicious mode
        #[cfg(not(feature = "malicious"))]
        let init_parties_t = InitParties::new(uid_count);
        #[cfg(feature = "malicious")]
        let init_parties_t = InitParties::new(uid_count, malicious_types);

        let (parties, party_uids) = init_parties(&init_parties_t, &dir).await;

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
        let sign_output = execute_sign(
            parties,
            &party_uids,
            sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
        )
        .await;

        let parties = sign_output.0;

        delete_dbs(&parties);
        shutdown_parties(parties).await;

        let results = sign_output.1;
        check_results(results, &sign_participant_indices, &expected_criminals);
    }
}

#[traced_test]
#[tokio::test]
async fn restart_one_party() {
    let dir = testdir!();

    for test_case in TEST_CASES.iter() {
        let uid_count = test_case.uid_count;
        let party_share_counts = &test_case.share_counts;
        let threshold = test_case.threshold;
        let sign_participant_indices = &test_case.signer_indices;
        let expected_criminals = &test_case.criminal_list;

        // get malicious types only when we are in malicious mode
        #[cfg(feature = "malicious")]
        let malicious_types = {
            let malicious_types = test_case.malicious_types.clone();
            match malicious_types.len() {
                0 => vec![Honest; uid_count],
                _ => malicious_types,
            }
        };

        // initialize parties with malicious_types when we are in malicious mode
        #[cfg(not(feature = "malicious"))]
        let init_parties_t = InitParties::new(uid_count);
        #[cfg(feature = "malicious")]
        let init_parties_t = InitParties::new(uid_count, malicious_types.clone());

        let (parties, party_uids) = init_parties(&init_parties_t, &dir).await;

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

        party_options[shutdown_index] = Some(TofndParty::new(init_party, &dir).await);
        let parties = party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>();

        // println!("sign: participants {:?}", sign_participant_indices);
        let new_sig_uid = "Gus-test-sig";
        let sign_output = execute_sign(
            parties,
            &party_uids,
            &sign_participant_indices,
            new_key_uid,
            new_sig_uid,
            &MSG_TO_SIGN,
        )
        .await;

        let parties = sign_output.0;

        delete_dbs(&parties);
        shutdown_parties(parties).await;

        let results = sign_output.1;
        check_results(results, &sign_participant_indices, &expected_criminals);
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
) -> (Vec<TofndParty>, Vec<String>) {
    let mut parties = Vec::with_capacity(init_parties.party_count);

    // use a for loop because async closures are unstable https://github.com/rust-lang/rust/issues/62290
    for i in 0..init_parties.party_count {
        // initialize party with respect to current build
        #[cfg(not(feature = "malicious"))]
        let init_party = InitParty::new(i);
        #[cfg(feature = "malicious")]
        let init_party = InitParty::new(i, init_parties.malicious_types.get(i).unwrap().clone());
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
) -> (Vec<impl Party>, Vec<proto::message_out::SignResult>) {
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
        sign_join_handles.push((participant_index, handle));
    }

    let mut results = Vec::new();
    // move participants back into party_options
    for (i, h) in sign_join_handles {
        let handle = h.await.unwrap();
        party_options[i] = Some(handle.0);
        results.push(handle.1);
    }
    (
        party_options
            .into_iter()
            .map(|o| o.unwrap())
            .collect::<Vec<_>>(),
        results,
    )
}
