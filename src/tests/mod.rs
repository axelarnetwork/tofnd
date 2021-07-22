// Notes:
// # Helper functions:
// Since we are using tokio, we need to make use of async function. That comes
// with the unfortunate necessity to declare some extra functions in order to
// facilitate the tests. These functions are:
// 1. src/kv_manager::KV::get_db_paths
// 2. src/gg20/mod::get_db_paths
// 3. src/gg20/mod::with_db_name

use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use testdir::testdir;

mod mock;
mod tofnd_party;

mod honest_test_cases;
#[cfg(feature = "malicious")]
mod malicious;
#[cfg(feature = "malicious")]
use malicious::{MaliciousData, PartyMaliciousData};

mod mnemonic;

use proto::message_out::CriminalList;
use tracing::info;

use crate::proto::{
    self,
    message_out::{
        keygen_result::KeygenResultData::{Criminals as KeygenCriminals, Data as KeygenData},
        sign_result::SignResultData::{Criminals as SignCriminals, Signature},
        KeygenResult, SignResult,
    },
};
use mock::{Deliverer, Party};
use tofnd_party::TofndParty;

// use crate::gg20::proto_helpers::to_criminals;

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42; 32];
    // TODO add test for messages smaller and larger than 32 bytes
}

struct TestCase {
    uid_count: usize,
    share_counts: Vec<u32>,
    threshold: usize,
    signer_indices: Vec<usize>,
    expected_keygen_faults: CriminalList,
    expected_sign_faults: CriminalList,
    #[cfg(feature = "malicious")]
    malicious_data: MaliciousData,
}

async fn run_test_cases(test_cases: &[TestCase]) {
    let restart = false;
    let delete_shares = false;
    let dir = testdir!();
    for test_case in test_cases {
        basic_keygen_and_sign(test_case, &dir, restart, delete_shares).await;
    }
}

async fn run_restart_test_cases(test_cases: &[TestCase]) {
    let restart = true;
    let delete_shares = false;
    let dir = testdir!();
    for test_case in test_cases {
        basic_keygen_and_sign(test_case, &dir, restart, delete_shares).await;
    }
}

async fn run_restart_recover_test_cases(test_cases: &[TestCase]) {
    let restart = true;
    let delete_shares = true;
    let dir = testdir!();
    for test_case in test_cases {
        basic_keygen_and_sign(test_case, &dir, restart, delete_shares).await;
    }
}

// Horrible code duplication indeed. Don't think we should spend time here though
// because this will be deleted when axelar-core accommodates crimes
fn successful_keygen_results(results: Vec<KeygenResult>, expected_faults: &CriminalList) -> bool {
    // get the first non-empty result. We can't simply take results[0] because some behaviours
    // don't return results and we pad them with `None`s
    let first = results.iter().find(|r| r.keygen_result_data.is_some());

    let mut pub_keys = vec![];
    for result in results.iter() {
        let res = match result.keygen_result_data.clone().unwrap() {
            KeygenData(data) => data.pub_key,
            KeygenCriminals(_) => continue,
        };
        pub_keys.push(res);
    }

    // else we have at least one result
    let first = first.unwrap().clone();
    match first.keygen_result_data {
        Some(KeygenData(data)) => {
            let first_pub_key = &data.pub_key;
            assert_eq!(
                expected_faults,
                &CriminalList::default(),
                "expected faults but none was found"
            );
            for (i, pub_key) in pub_keys.iter().enumerate() {
                assert_eq!(
                    first_pub_key, pub_key,
                    "party {} didn't produce the expected pub_key",
                    i
                );
            }
        }
        Some(KeygenCriminals(ref actual_faults)) => {
            assert_eq!(expected_faults, actual_faults);
            info!("Fault list: {:?}", expected_faults);
            return false;
        }
        None => {
            panic!("Result was None");
        }
    }
    true
}

// Horrible code duplication indeed. Don't think we should spend time here though
// because this will be deleted when axelar-core accommodates crimes
fn check_sign_results(results: Vec<SignResult>, expected_faults: &CriminalList) -> bool {
    // get the first non-empty result. We can't simply take results[0] because some behaviours
    // don't return results and we pad them with `None`s
    let first = results.iter().find(|r| r.sign_result_data.is_some());

    let mut pub_keys = vec![];
    for result in results.iter() {
        let res = match result.sign_result_data.clone().unwrap() {
            Signature(signature) => signature,
            SignCriminals(_) => continue,
        };
        pub_keys.push(res);
    }

    // else we have at least one result
    let first = first.unwrap().clone();
    match first.sign_result_data {
        Some(Signature(signature)) => {
            let first_signature = signature;
            assert_eq!(
                expected_faults,
                &CriminalList::default(),
                "expected faults but none was found"
            );
            for (i, signature) in pub_keys.iter().enumerate() {
                assert_eq!(
                    &first_signature, signature,
                    "party {} didn't produce the expected signature",
                    i
                );
            }
        }
        Some(SignCriminals(ref actual_faults)) => {
            assert_eq!(expected_faults, actual_faults);
            info!("Fault list: {:?}", expected_faults);
            return false;
        }
        None => {
            panic!("Result was None");
        }
    }
    true
}

fn gather_recover_info(results: &[KeygenResult]) -> Vec<Vec<u8>> {
    // gather recover info
    let mut recover_infos = vec![];
    for result in results.iter() {
        let result_data = result.keygen_result_data.clone().unwrap();
        match result_data {
            KeygenData(output) => {
                recover_infos.extend(output.share_recovery_infos.clone());
            }
            KeygenCriminals(_) => {}
        }
    }
    recover_infos
}

// shutdown i-th party
// returns i-th party's db path and a vec of Option<TofndParty> that contain all parties (including i-th)
async fn shutdown_party(
    parties: Vec<TofndParty>,
    party_index: usize,
) -> (Vec<Option<TofndParty>>, PathBuf) {
    info!("shutdown party {}", party_index);
    let party_db_path = parties[party_index].get_db_path();
    // use Option to temporarily transfer ownership of individual parties to a spawn
    let mut party_options: Vec<Option<_>> = parties.into_iter().map(Some).collect();
    let shutdown_party = party_options[party_index].take().unwrap();
    shutdown_party.shutdown().await;
    (party_options, party_db_path)
}

// deletes the share kv-store of a party's db path
fn delete_party_shares(mut party_db_path: PathBuf) {
    party_db_path.push("shares");
    // Sled creates a directory for the database and its configuration
    info!("removing shares kv-store of party {:?}", party_db_path);
    std::fs::remove_dir_all(party_db_path).unwrap();
}

// initailizes i-th party
// pass malicious data if we are running in malicious mode
async fn init_party(
    mut party_options: Vec<Option<TofndParty>>,
    party_index: usize,
    testdir: &Path,
    #[cfg(feature = "malicious")] malicious_data: &MaliciousData,
) -> Vec<TofndParty> {
    // initialize restarted party with its previous behaviour if we are in malicious mode
    let init_party = InitParty::new(
        party_index,
        #[cfg(feature = "malicious")]
        malicious_data,
    );

    // assume party already has a mnemonic, so we pass Cmd::Noop
    party_options[party_index] =
        Some(TofndParty::new(init_party, crate::gg20::mnemonic::Cmd::Noop, &testdir).await);

    party_options
        .into_iter()
        .map(|o| o.unwrap())
        .collect::<Vec<_>>()
}

// delete all kv-stores of all parties and kill servers
async fn clean_up(parties: Vec<TofndParty>) {
    delete_dbs(&parties);
    shutdown_parties(parties).await;
}

// create parties that will participate in keygen/sign from testcase args
async fn init_parties_from_test_case(
    test_case: &TestCase,
    dir: &Path,
) -> (Vec<TofndParty>, Vec<String>) {
    #[cfg(not(feature = "malicious"))]
    let init_parties_t = InitParties::new(test_case.uid_count);
    #[cfg(feature = "malicious")]
    let init_parties_t = InitParties::new(test_case.uid_count, &test_case.malicious_data);
    init_parties(&init_parties_t, &dir).await
}

// keygen wrapper
async fn basic_keygen(
    test_case: &TestCase,
    parties: Vec<TofndParty>,
    party_uids: Vec<String>,
    new_key_uid: &str,
) -> (Vec<TofndParty>, proto::KeygenInit, Vec<KeygenResult>, bool) {
    let party_share_counts = &test_case.share_counts;
    let threshold = test_case.threshold;
    let expected_keygen_faults = &test_case.expected_keygen_faults;

    info!(
        "======= Expected keygen crimes: {:?}",
        expected_keygen_faults
    );

    #[cfg(not(feature = "malicious"))]
    let expect_timeout = false;
    #[cfg(feature = "malicious")]
    let expect_timeout = test_case.malicious_data.keygen_data.timeout.is_some();

    let (parties, results, keygen_init) = execute_keygen(
        parties,
        &party_uids,
        party_share_counts,
        new_key_uid,
        threshold,
        expect_timeout,
    )
    .await;

    let success = successful_keygen_results(results.clone(), &expected_keygen_faults);
    (parties, keygen_init, results, success)
}

// restart i-th and optionally delete its shares kv-store
async fn restart_party(
    dir: &Path,
    parties: Vec<TofndParty>,
    party_index: usize,
    delete_shares: bool,
    #[cfg(feature = "malicious")] malicious_data: &MaliciousData,
) -> Vec<TofndParty> {
    // shutdown party with party_index
    let (party_options, shutdown_db_path) = shutdown_party(parties, party_index).await;

    if delete_shares {
        // delete party's shares
        delete_party_shares(shutdown_db_path);
    }

    // reinit party with
    let parties = init_party(
        party_options,
        party_index,
        dir,
        #[cfg(feature = "malicious")]
        &malicious_data,
    )
    .await;
    parties
}

// main testing function
async fn basic_keygen_and_sign(
    test_case: &TestCase,
    dir: &Path,
    restart: bool,
    delete_shares: bool,
) {
    // don't allow to delete shares without restarting
    if delete_shares && !restart {
        panic!("cannot delete shares without restarting");
    }

    // set up a key uid
    let new_key_uid = "Gus-test-key";

    // use test case params to create parties
    let (parties, party_uids) = init_parties_from_test_case(test_case, dir).await;

    // execute keygen and return everything that will be needed later on
    let (parties, keygen_init, keygen_results, success) =
        basic_keygen(test_case, parties, party_uids.clone(), new_key_uid).await;

    if !success {
        clean_up(parties).await;
        return;
    }

    // restart party if restart is enabled and return new parties' set
    let parties = match restart {
        true => {
            restart_party(
                &dir,
                parties,
                test_case.signer_indices[0],
                delete_shares,
                #[cfg(feature = "malicious")]
                &test_case.malicious_data,
            )
            .await
        }
        false => parties,
    };

    // delete party's if recover is enabled and return new parties' set
    let parties = match delete_shares {
        true => {
            execute_recover(
                parties,
                test_case.signer_indices[0],
                keygen_init,
                gather_recover_info(&keygen_results),
            )
            .await
        }
        false => parties,
    };

    let expected_sign_faults = &test_case.expected_sign_faults;
    #[cfg(not(feature = "malicious"))]
    let expect_timeout = false;
    #[cfg(feature = "malicious")]
    let expect_timeout = test_case.malicious_data.sign_data.timeout.is_some();

    // execute sign
    let new_sig_uid = "Gus-test-sig";
    let (parties, results) = execute_sign(
        parties,
        &party_uids,
        &test_case.signer_indices,
        new_key_uid,
        new_sig_uid,
        &MSG_TO_SIGN,
        expect_timeout,
    )
    .await;
    check_sign_results(results, &expected_sign_faults);

    clean_up(parties).await;
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
        // register timeouts
        let mut timeout_round = 0;
        if let Some(timeout) = all_malicious_data.keygen_data.timeout.clone() {
            if timeout.index == my_index {
                timeout_round = timeout.round;
            }
        }
        if let Some(timeout) = all_malicious_data.sign_data.timeout.clone() {
            if timeout.index == my_index {
                timeout_round = timeout.round;
            }
        }

        // register disrupts
        let mut disrupt_round = 0;
        if let Some(disrupt) = all_malicious_data.keygen_data.disrupt.clone() {
            if disrupt.index == my_index {
                disrupt_round = disrupt.round;
            }
        }
        if let Some(disrupt) = all_malicious_data.sign_data.disrupt.clone() {
            if disrupt.index == my_index {
                disrupt_round = disrupt.round;
            }
        }

        let my_keygen_behaviour = all_malicious_data
            .keygen_data
            .behaviours
            .get(my_index)
            .unwrap()
            .clone();

        // let my_sign_behaviour = all_malicious_data
        //     .sign_data
        //     .behaviours
        //     .get(my_index)
        //     .unwrap()
        //     .clone();

        let my_malicious_data = PartyMaliciousData {
            timeout_round,
            disrupt_round,
            keygen_behaviour: my_keygen_behaviour,
            // sign_behaviour: my_sign_behaviour,
        };

        InitParty {
            party_index: my_index,
            malicious_data: my_malicious_data,
        }
    }
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
        parties
            .push(TofndParty::new(init_party, crate::gg20::mnemonic::Cmd::Create, testdir).await);
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
    expect_timeout: bool,
) -> (Vec<TofndParty>, Vec<KeygenResult>, proto::KeygenInit) {
    info!("Expecting timeout: [{}]", expect_timeout);
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
            let result = party.execute_keygen(init, channel_pair, delivery).await;
            (party, result)
        });
        keygen_join_handles.push(handle);
    }

    // if we are expecting a timeout, abort parties after a reasonable amount of time
    if expect_timeout {
        let unblocker = keygen_delivery.clone();
        abort_parties(unblocker, 10);
    }

    let mut parties = Vec::with_capacity(share_count); // async closures are unstable https://github.com/rust-lang/rust/issues/62290
    let mut results = vec![];
    for h in keygen_join_handles {
        let handle = h.await.unwrap();
        parties.push(handle.0);
        results.push(handle.1);
    }
    let init = proto::KeygenInit {
        new_key_uid: new_key_uid.to_string(),
        party_uids: party_uids.to_owned(),
        party_share_counts: party_share_counts.to_owned(),
        my_party_index: 0, // return keygen for first party. Might need to change index before using
        threshold: i32::try_from(threshold).unwrap(),
    };
    (parties, results, init)
}

async fn execute_recover(
    mut parties: Vec<TofndParty>,
    recover_party_index: usize,
    mut keygen_init: proto::KeygenInit,
    recovery_infos: Vec<Vec<u8>>,
) -> Vec<TofndParty> {
    // create keygen init for recovered party
    keygen_init.my_party_index = recover_party_index as i32;
    parties[recover_party_index]
        .execute_recover(keygen_init, recovery_infos)
        .await;
    parties
}

// need to take ownership of parties `parties` and return it on completion
async fn execute_sign(
    parties: Vec<TofndParty>,
    party_uids: &[String],
    sign_participant_indices: &[usize],
    key_uid: &str,
    new_sig_uid: &str,
    msg_to_sign: &[u8],
    expect_timeout: bool,
) -> (Vec<TofndParty>, Vec<proto::message_out::SignResult>) {
    info!("Expecting timeout: [{}]", expect_timeout);
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

    // if we are expecting a timeout, abort parties after a reasonable amount of time
    if expect_timeout {
        let unblocker = sign_delivery.clone();
        abort_parties(unblocker, 10);
    }

    let mut results = vec![SignResult::default(); sign_join_handles.len()];
    for (i, h) in sign_join_handles {
        info!("Running party {}", i);
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

fn abort_parties(mut unblocker: Deliverer, time: u64) {
    // send an abort message if protocol is taking too much time
    info!("I will send an abort message in {} seconds", time);
    std::thread::spawn(move || {
        unblocker.send_timeouts(time);
    });
    info!("Continuing for now");
}
