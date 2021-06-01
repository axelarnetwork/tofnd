use tofn::protocol::gg20::keygen::{
    crimes::Crime,
    malicious::Behaviour::{self, *},
    MsgType, Status,
};

use super::super::{run_test_cases, TestCase};
use super::{MaliciousData, MsgType::KeygenMsgType, Timeout};

use serde::{Deserialize, Serialize}; // we assume bad guys know how to (de)serialize
use strum::IntoEnumIterator; // iterate malicious types, message types and statuses
use tracing_test::traced_test; // log for tests

#[traced_test]
#[tokio::test]
async fn keygen_malicious_general_cases() {
    run_test_cases(&generate_basic_cases(), false).await;
}

#[traced_test]
#[tokio::test]
async fn keygen_malicious_multiple_per_round() {
    run_test_cases(&generate_multiple_malicious_per_round(), false).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_timeout_cases() {
    run_test_cases(&timeout_cases(), false).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_spoof_cases() {
    run_test_cases(&spoof_cases(), false).await;
}

#[derive(Clone, Debug)]
pub(crate) struct Spoof {
    pub(crate) index: usize,
    pub(crate) victim: usize,
    pub(crate) status: Status,
}

impl Spoof {
    pub(crate) fn msg_to_status(msg_type: &MsgType) -> Status {
        match msg_type {
            MsgType::R1Bcast => Status::R1,
            MsgType::R2Bcast => Status::R2,
            MsgType::R2P2p { to: _ } => Status::R2,
            MsgType::R3Bcast => Status::R3,
            MsgType::R3FailBcast => Status::R3,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct KeygenData {
    pub(crate) behaviours: Vec<Behaviour>,
    pub(crate) timeout: Option<Timeout>,
    pub(crate) spoof: Option<Spoof>,
}

impl KeygenData {
    pub(super) fn empty(party_count: usize) -> KeygenData {
        KeygenData {
            behaviours: vec![Honest; party_count],
            timeout: None,
            spoof: None,
        }
    }
}

pub(super) struct Keygener {
    pub(super) behaviour: Behaviour,
    pub(super) expected_crimes: Vec<Crime>,
}

impl Keygener {
    fn new(behaviour: Behaviour, expected_crimes: Vec<Crime>) -> Self {
        Keygener {
            behaviour,
            expected_crimes,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MsgMeta {
    pub(crate) msg_type: MsgType,
    pub(crate) from: usize,
    pub(crate) payload: Vec<u8>,
}

impl TestCase {
    fn new_malicious_keygen(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        keygen_participants: Vec<Keygener>,
    ) -> TestCase {
        let behaviours: Vec<Behaviour> = keygen_participants
            .iter()
            .map(|kp| kp.behaviour.clone())
            .collect();

        let expected_keygen_crimes: Vec<Vec<Crime>> = keygen_participants
            .iter()
            .map(|kp| kp.expected_crimes.clone())
            .collect();

        let mut timeout: Option<Timeout> = None;
        for (i, t) in behaviours.iter().enumerate() {
            if let Staller { msg_type } = t {
                timeout = Some(Timeout {
                    index: i,
                    msg_type: KeygenMsgType {
                        msg_type: msg_type.clone(),
                    },
                });
            }
        }

        let mut spoof: Option<Spoof> = None;
        for (i, t) in behaviours.iter().enumerate() {
            if let UnauthenticatedSender { victim, status } = t {
                spoof = Some(Spoof {
                    index: i,
                    victim: *victim,
                    status: status.clone(),
                });
            }
        }

        let mut malicious_data = MaliciousData::empty(uid_count);
        malicious_data.set_keygen_data(KeygenData {
            behaviours,
            timeout,
            spoof,
        });

        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices: vec![],
            expected_keygen_crimes,
            expected_sign_crimes: vec![],
            malicious_data,
        }
    }
}

fn to_crime(behaviour: &Behaviour) -> Crime {
    match behaviour {
        Honest => panic!("`to_crime` called with `Honest`"),
        Staller { msg_type: mt } => Crime::StalledMessage {
            msg_type: mt.clone(),
        },
        UnauthenticatedSender {
            victim: v,
            status: s,
        } => Crime::SpoofedMessage {
            victim: *v,
            status: s.clone(),
        },
        DisruptingSender { msg_type: _ } => Crime::DisruptedMessage,
        R1BadCommit => Crime::R3BadReveal,
        R2BadShare { victim: v } => Crime::R4FailBadVss { victim: *v },
        R2BadEncryption { victim: v } => Crime::R4FailBadEncryption { victim: *v },
        R3FalseAccusation { victim: v } => Crime::R4FailFalseAccusation { victim: *v },
    }
}

fn generate_basic_cases() -> Vec<TestCase> {
    let mut cases = vec![];
    for m in Behaviour::iter().filter(|m| {
        // don't include malicious types that happen at the routing level
        !matches!(
            m,
            Honest
                | UnauthenticatedSender {
                    victim: _,
                    status: _
                }
                | Staller { msg_type: _ }
                | DisruptingSender { msg_type: _ }
        )
    }) {
        cases.push(TestCase::new_malicious_keygen(
            4,
            vec![1, 2, 1, 3],
            3,
            vec![
                Keygener::new(Honest, vec![]),
                Keygener::new(Honest, vec![]),
                Keygener::new(Honest, vec![]),
                Keygener::new(m.clone(), vec![to_crime(&m)]),
            ],
        ));
    }
    cases
}

fn generate_multiple_malicious_per_round() -> Vec<TestCase> {
    let victim = 0;
    let all_rounds_faults = vec![
        // round 2 faults
        vec![R2BadEncryption { victim }, R2BadShare { victim }],
        // round 3 faults
        vec![R3FalseAccusation { victim }],
        // round 1 faults
        // vec![R1BadCommit], // exclude round 1 faults because they stall

        // Why do the above test cases stall?
        // All of the above behaviours result to a crime that is captured at the same round it occurs.
        // This means that honest parties immediately stop the protocol, but criminals do not receive
        // all messages they expect for that round.
        // If we want to make the protocol finish successfully for all parties in these test cases, we
        // can assign multiple shares to these types, so that each malicious share will to notify the
        // rest of the shares that the protocol has ended, or trigger the timeout mechanism.
    ];
    // create test cases for all rounds
    let mut cases = Vec::new();
    for round_faults in all_rounds_faults {
        let mut participants = vec![Keygener::new(Honest, vec![])];
        for fault in round_faults.into_iter() {
            participants.push(Keygener::new(
                fault.clone(), // behaviour data initialized with Default:default()
                vec![to_crime(&fault)],
            ));
        }
        cases.push(TestCase::new_malicious_keygen(
            participants.len(),
            vec![1; participants.len()],
            participants.len() - 1, // threshold < #parties
            participants,
        ));
    }
    cases
}

fn timeout_cases() -> Vec<TestCase> {
    use MsgType::*;
    let stallers = MsgType::iter()
        .filter(|msg_type| matches!(msg_type, R1Bcast | R2Bcast | R2P2p { to: _ } | R3Bcast,)) // don't match fail types
        .map(|msg_type| Staller { msg_type })
        .collect::<Vec<Behaviour>>();

    // staller always targets party 0
    stallers
        .iter()
        .map(|staller| {
            TestCase::new_malicious_keygen(
                4,
                vec![1, 1, 1, 1],
                2,
                vec![
                    Keygener::new(Honest, vec![]),
                    Keygener::new(staller.clone(), vec![to_crime(&staller)]),
                    Keygener::new(Honest, vec![]),
                    Keygener::new(Honest, vec![]),
                ],
            )
        })
        .collect()
}

fn spoof_cases() -> Vec<TestCase> {
    use Status::*;
    let victim = 0;
    let spoofers = Status::iter()
        .filter(|status| matches!(status, R1 | R2 | R3)) // don't match fail types
        .map(|status| UnauthenticatedSender { victim, status })
        .collect::<Vec<Behaviour>>();

    // spoofer always targets party 0
    spoofers
        .iter()
        .map(|spoofer| {
            TestCase::new_malicious_keygen(
                5,
                vec![1, 1, 1, 1, 1],
                3,
                vec![
                    Keygener::new(Honest, vec![]),
                    Keygener::new(spoofer.clone(), vec![to_crime(&spoofer)]),
                    Keygener::new(Honest, vec![]),
                    Keygener::new(Honest, vec![]),
                    Keygener::new(Honest, vec![]),
                ],
            )
        })
        .collect()
}
