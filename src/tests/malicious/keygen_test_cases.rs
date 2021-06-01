use tofn::protocol::gg20::keygen::{
    crimes::Crime,
    malicious::Behaviour::{self, *},
    MsgType, Status,
};

use super::super::{run_test_cases, TestCase};
use super::MaliciousData;

use serde::{Deserialize, Serialize}; // we assume bad guys know how to (de)serialize
use strum::IntoEnumIterator; // iterate malicious types, message types and statuses
use tracing_test::traced_test; // log for tests

#[traced_test]
#[tokio::test]
async fn keygen_malicious_general_cases() {
    run_test_cases(&generate_basic_cases(), false).await;
}

#[derive(Clone, Debug)]
pub(crate) struct Timeout {
    pub(crate) index: usize,
    pub(crate) msg_type: MsgType,
}
#[derive(Clone, Debug)]
pub(crate) struct Spoof {
    pub(crate) index: usize,
    pub(crate) victim: usize,
    pub(crate) status: Status,
}

impl Spoof {
    pub(super) fn _msg_to_status(msg_type: &MsgType) -> Status {
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
pub(super) struct MsgMeta {
    pub(super) msg_type: MsgType,
    pub(super) from: usize,
    pub(super) payload: Vec<u8>,
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
                    msg_type: msg_type.clone(),
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
            expected_crimes: vec![],
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
