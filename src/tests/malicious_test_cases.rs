use tofn::protocol::gg20::sign::{
    crimes::Crime,
    malicious::MaliciousType::{self, *},
    MsgType, Status,
};

use crate::tests::TestCase;
use crate::tests::{run_test_cases, run_test_cases_with_restart};

use serde::{Deserialize, Serialize}; // we assume bad guys know how to (de)serialize
use strum::IntoEnumIterator; // iterate malicious types, message types and statuses
use tracing_test::traced_test; // log for tests

#[traced_test]
#[tokio::test]
async fn malicious_general_cases() {
    run_test_cases(&generate_basic_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_general_cases_with_restart() {
    run_test_cases_with_restart(&generate_basic_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_multiple_per_round_cases() {
    run_test_cases(&generate_multiple_malicious_per_round()).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_timeout_cases() {
    run_test_cases(&timeout_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_spoof_cases() {
    run_test_cases(&spoof_cases()).await;
}

// TODO import that from tofn
pub(super) fn map_type_to_crime(t: &MaliciousType) -> Vec<Crime> {
    match t {
        Honest => vec![],
        Staller { msg_type: mt } => vec![Crime::StalledMessage {
            msg_type: mt.clone(),
        }],
        UnauthenticatedSender {
            victim: v,
            status: s,
        } => vec![Crime::SpoofedMessage {
            victim: *v,
            status: s.clone(),
        }],
        R1BadProof { victim: v } => vec![Crime::R3FailBadRangeProof { victim: *v }],
        R2FalseAccusation { victim: v } => vec![Crime::R3FailFalseAccusation { victim: *v }],
        R2BadMta { victim: v } => vec![Crime::R4FailBadRangeProof { victim: *v }],
        R2BadMtaWc { victim: v } => vec![Crime::R4FailBadRangeProof { victim: *v }],
        R3FalseAccusationMta { victim: v } => vec![Crime::R4FailFalseAccusation { victim: *v }],
        R3FalseAccusationMtaWc { victim: v } => vec![Crime::R4FailFalseAccusation { victim: *v }],
        R3BadProof => vec![Crime::R4BadPedersenProof],
        R4BadReveal => vec![Crime::R5BadHashCommit],
        R5BadProof { victim: v } => vec![Crime::R7FailBadRangeProof { victim: *v }],
        R6FalseAccusation { victim: v } => vec![Crime::R7FailFalseAccusation { victim: *v }],
        R6BadProof => vec![Crime::R7BadRangeProof],
        R7BadSigSummand => vec![Crime::R8BadSigSummand],
        R3BadNonceXBlindSummand => vec![Crime::R7FailType5BadNonceXBlindSummand],
        R3BadEcdsaNonceSummand => vec![Crime::R7FailType5BadNonceSummand],
        R1BadSecretBlindSummand => vec![Crime::R7FailType5BadBlindSummand],
        R3BadMtaBlindSummandRhs { victim: v } => {
            vec![Crime::R7FailType5MtaBlindSummandRhs { victim: *v }]
        }
        R3BadMtaBlindSummandLhs { victim: v } => {
            vec![Crime::R7FailType5MtaBlindSummandLhs { victim: *v }]
        }
        R6FalseFailRandomizer => vec![Crime::R7FailType5FalseComplaint],
        R3BadNonceXKeyshareSummand => vec![Crime::R8FailType7BadZkp],
    }
}
pub(super) struct Signer {
    pub(super) party_index: usize,
    pub(super) behaviour: MaliciousType,
    pub(super) expected_crimes: Vec<Crime>,
}

impl Signer {
    pub(super) fn new(
        party_index: usize,
        behaviour: MaliciousType,
        expected_crimes: Vec<Crime>,
    ) -> Self {
        Signer {
            party_index,
            behaviour,
            expected_crimes,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct MsgMeta {
    pub(super) msg_type: MsgType,
    pub(super) from: usize,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) struct Timeout {
    pub(super) index: usize,
    pub(super) msg_type: MsgType,
}
#[derive(Clone, Debug)]
pub(super) struct Spoof {
    pub(super) index: usize,
    pub(super) victim: usize,
    pub(super) status: Status,
}

pub(super) struct MaliciousData {
    pub(super) malicious_types: Vec<MaliciousType>,
    pub(super) timeout: Option<Timeout>,
    pub(super) spoof: Option<Spoof>,
}

impl Spoof {
    pub(super) fn msg_to_status(msg_type: &MsgType) -> Status {
        match msg_type {
            MsgType::R1Bcast => Status::R1,
            MsgType::R1P2p { to: _ } => Status::R1,
            MsgType::R2P2p { to: _ } => Status::R2,
            MsgType::R2FailBcast => Status::R2,
            MsgType::R3Bcast => Status::R3,
            MsgType::R3FailBcast => Status::R3,
            MsgType::R4Bcast => Status::R4,
            MsgType::R5Bcast => Status::R5,
            MsgType::R5P2p { to: _ } => Status::R5,
            MsgType::R6Bcast => Status::R6,
            MsgType::R6FailBcast => Status::R6,
            MsgType::R6FailType5Bcast => Status::R6,
            MsgType::R7Bcast => Status::R7,
            MsgType::R7FailType7Bcast => Status::R7,
        }
    }
}

impl TestCase {
    pub(super) fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        sign_participants: Vec<Signer>,
    ) -> TestCase {
        // we use the Signer struct to allign the beaviour type with the index of each signer
        // However, in the context of tofnd, behaviour is not only related with signers, but with
        // init_party, as well. That is, because we need to initialize a Gg20 service for both
        // signers and non-signers. We build these vectors from user's input `sign_participants`:
        // 1. crimial_list -> holds the tofnd index of every criminal
        // 2. malicious_types -> holds the behaviour of every party (not just signers) and is alligned with tofnd party uids
        // 3. signer_indices -> holds the tofnd index of every signer
        let mut signer_indices = Vec::new();
        let mut signer_behaviours = Vec::new();
        let mut signer_crimes = Vec::new();

        // could be more rusty but take double the LoC
        for sign_participant in sign_participants.iter() {
            signer_indices.push(sign_participant.party_index);
            signer_behaviours.push(sign_participant.behaviour.clone());
            signer_crimes.push(sign_participant.expected_crimes.clone());
        }

        let mut malicious_types = Vec::new();
        let mut expected_crimes = Vec::new();
        for i in 0..uid_count {
            if !signer_indices.contains(&i) {
                expected_crimes.push(vec![]);
                malicious_types.push(Honest);
            } else {
                let signer_index = signer_indices.iter().position(|&idx| idx == i).unwrap();
                let signer_type = signer_behaviours[signer_index].clone();
                malicious_types.push(signer_type);
                let signer_crimes = signer_crimes[signer_index].clone();
                expected_crimes.push(signer_crimes);
            }
        }

        let mut timeout: Option<Timeout> = None;
        for (i, t) in malicious_types.iter().enumerate() {
            if let Staller { msg_type } = t {
                timeout = Some(Timeout {
                    index: i,
                    msg_type: msg_type.clone(),
                });
            }
        }

        let mut spoof: Option<Spoof> = None;
        for (i, t) in malicious_types.iter().enumerate() {
            if let UnauthenticatedSender { victim, status } = t {
                spoof = Some(Spoof {
                    index: i,
                    victim: *victim,
                    status: status.clone(),
                });
            }
        }

        let malicious_data = MaliciousData {
            malicious_types,
            timeout,
            spoof,
        };

        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            expected_crimes,
            malicious_data,
        }
    }
}

pub(super) fn timeout_cases() -> Vec<TestCase> {
    use MsgType::*;
    let stallers = MsgType::iter()
        .filter(|msg_type| {
            matches!(
                msg_type,
                R1Bcast
                    | R1P2p { to: _ }
                    | R2P2p { to: _ }
                    | R3Bcast
                    | R4Bcast
                    | R5Bcast
                    | R5P2p { to: _ }
                    | R6Bcast
                    | R7Bcast
            )
        }) // don't match fail types
        .map(|msg_type| Staller { msg_type })
        .collect::<Vec<MaliciousType>>();

    // staller always targets party 0
    stallers
        .iter()
        .map(|staller| {
            TestCase::new(
                4,
                vec![1, 1, 1, 1],
                2,
                vec![
                    Signer::new(0, Honest, vec![]),
                    Signer::new(1, staller.clone(), map_type_to_crime(&staller)),
                    Signer::new(2, Honest, vec![]),
                ],
            )
        })
        .collect()
}

pub(super) fn spoof_cases() -> Vec<TestCase> {
    use Status::*;
    let victim = 0;
    let spoofers = Status::iter()
        .filter(|status| matches!(status, R1 | R2 | R3 | R4 | R5 | R6 | R7)) // don't match fail types
        .map(|status| UnauthenticatedSender { victim, status })
        .collect::<Vec<MaliciousType>>();

    // spoofer always targets party 0
    spoofers
        .iter()
        .map(|spoofer| {
            TestCase::new(
                5,
                vec![1, 1, 1, 1, 1],
                3,
                vec![
                    Signer::new(0, Honest, vec![]),
                    Signer::new(1, spoofer.clone(), map_type_to_crime(&spoofer)),
                    Signer::new(2, Honest, vec![]),
                    Signer::new(3, Honest, vec![]),
                    Signer::new(4, Honest, vec![]),
                ],
            )
        })
        .collect()
}

pub(super) fn generate_basic_cases() -> Vec<TestCase> {
    let mut cases = vec![];
    for m in MaliciousType::iter().filter(|m| {
        // don't include malicious types that happen at the routing level
        !matches!(
            m,
            UnauthenticatedSender {
                victim: _,
                status: _
            } | Staller { msg_type: _ }
        )
    }) {
        cases.push(TestCase::new(
            4,
            vec![1, 2, 1, 3],
            3,
            vec![
                Signer::new(0, Honest, vec![]),
                Signer::new(1, Honest, vec![]),
                Signer::new(2, Honest, vec![]),
                Signer::new(3, m.clone(), map_type_to_crime(&m)),
            ],
        ));
    }
    cases
}

pub(super) fn generate_multiple_malicious_per_round() -> Vec<TestCase> {
    let victim = 0;
    let all_rounds_faults = vec![
        // round 1 faults
        vec![R1BadProof { victim }, R2FalseAccusation { victim }],
        // round 2 faults
        vec![
            R2BadMta { victim },
            R2BadMtaWc { victim },
            R3FalseAccusationMta { victim },
            R3FalseAccusationMtaWc { victim },
        ],
        // round 5 faults
        vec![R5BadProof { victim }, R6FalseAccusation { victim }],
        // round 7 faults
        vec![R7BadSigSummand],
        // vec![R3BadProof], // exclude round 3 faults because they stall
        // vec![R4BadReveal], // exclude round 4 faults because they stall
        // vec![R6BadProof], // exclude round 6 faults because they stall
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
        // start with the victim at pos 0
        let mut participants = vec![Signer::new(
            round_faults.len(), // give the good guy the last party index
            Honest,
            vec![],
        )];
        for (i, fault) in round_faults.into_iter().enumerate() {
            participants.push(Signer::new(
                i,
                fault.clone(), // behaviour data initialized with Default:default()
                map_type_to_crime(&fault),
            ));
        }
        cases.push(TestCase::new(
            5,
            vec![1, 1, 1, 1, 3],
            participants.len() - 1, // threshold < #parties
            participants,
        ));
    }
    cases
}
