use crate::proto::message_out::{
    criminal_list::{criminal::CrimeType, Criminal},
    CriminalList,
};
use tofn::refactor::collections::TypedUsize;

use tofn::refactor::keygen::malicious::Behaviour::{self, *};

use super::super::{run_test_cases, TestCase};
use super::{Disrupt, MaliciousData, Timeout};

use tracing_test::traced_test; // log for tests

#[traced_test]
#[tokio::test]
async fn keygen_malicious_general_cases() {
    run_test_cases(&generate_basic_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn keygen_malicious_multiple_per_round() {
    run_test_cases(&generate_multiple_malicious_per_round()).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_timeout_cases() {
    run_test_cases(&timeout_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn malicious_disrupt_cases() {
    run_test_cases(&disrupt_cases()).await;
}

#[derive(Clone, Debug)]
pub(crate) struct KeygenData {
    pub(crate) behaviours: Vec<Behaviour>,
    pub(crate) timeout: Option<Timeout>,
    pub(crate) disrupt: Option<Disrupt>,
}

impl KeygenData {
    pub(super) fn empty(party_count: usize) -> KeygenData {
        KeygenData {
            behaviours: vec![Honest; party_count],
            timeout: None,
            disrupt: None,
        }
    }
}

impl TestCase {
    fn new_malicious_keygen(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        behaviours: Vec<Behaviour>,
    ) -> TestCase {
        // expected faults: Vec<Criminals{party_uid:<>, crime_type: CrimeType::Malicious}>
        let mut expected_faults = vec![];
        for (i, behaviour) in behaviours.iter().enumerate() {
            if matches!(behaviour, &Behaviour::Honest) {
                continue;
            }
            expected_faults.push(Criminal {
                party_uid: (('A' as u8 + i as u8) as char).to_string(),
                crime_type: CrimeType::Malicious as i32,
            });
        }
        let expected_faults = CriminalList {
            criminals: expected_faults,
        };

        let mut malicious_data = MaliciousData::empty(uid_count);
        malicious_data.set_keygen_data(KeygenData {
            behaviours,
            timeout: None,
            disrupt: None,
        });

        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices: vec![],
            expected_keygen_faults: expected_faults,
            expected_sign_faults: CriminalList::default(),
            malicious_data,
        }
    }

    fn with_timeout(mut self, index: usize, round: usize) -> Self {
        self.malicious_data.keygen_data.timeout = Some(Timeout { index, round });
        self.expected_keygen_faults = CriminalList {
            criminals: vec![Criminal {
                party_uid: (('A' as u8 + index as u8) as char).to_string(),
                crime_type: CrimeType::NonMalicious as i32,
            }],
        };
        self
    }

    fn with_disrupt(mut self, index: usize, round: usize) -> Self {
        self.malicious_data.keygen_data.disrupt = Some(Disrupt { index, round });
        self.expected_keygen_faults = CriminalList {
            criminals: vec![Criminal {
                party_uid: (('A' as u8 + index as u8) as char).to_string(),
                crime_type: CrimeType::Unspecified as i32,
            }],
        };
        self
    }
}

fn generate_basic_cases() -> Vec<TestCase> {
    let behaviours = vec![
        Honest,
        R1BadCommit,
        R1BadEncryptionKeyProof,
        R1BadZkSetupProof,
        R2BadShare {
            victim: TypedUsize::from_usize(0),
        },
        R2BadEncryption {
            victim: TypedUsize::from_usize(0),
        },
        R3FalseAccusation {
            victim: TypedUsize::from_usize(0),
        },
        R3BadXIWitness,
    ];

    behaviours
        .into_iter()
        .map(|b| {
            TestCase::new_malicious_keygen(4, vec![1, 2, 1, 3], 3, vec![Honest, Honest, Honest, b])
        })
        .collect()
}

fn generate_multiple_malicious_per_round() -> Vec<TestCase> {
    let victim = TypedUsize::from_usize(0);
    let all_rounds_faults = vec![
        // round 1 faults
        vec![R1BadCommit],
        // round 2 faults
        vec![R2BadEncryption { victim }, R2BadShare { victim }],
        // round 3 faults
        vec![R3FalseAccusation { victim }],
    ];
    // create test cases for all rounds
    let mut cases = Vec::new();
    for round_faults in all_rounds_faults {
        let mut participants = vec![Honest];
        for fault in round_faults.into_iter() {
            participants.push(fault.clone()); // behaviour data initialized with Default:default()
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
    let timeout_rounds = vec![1, 2, 3];
    timeout_rounds
        .into_iter()
        .map(|r| {
            TestCase::new_malicious_keygen(3, vec![1, 1, 1], 2, vec![Honest, Honest, Honest])
                .with_timeout(0, r) // add timeout party at index 0
        })
        .collect()
}

fn disrupt_cases() -> Vec<TestCase> {
    let disrupt_rounds = vec![1, 2, 3];
    disrupt_rounds
        .into_iter()
        .map(|r| {
            TestCase::new_malicious_keygen(3, vec![1, 1, 1], 2, vec![Honest, Honest, Honest])
                .with_disrupt(0, r) // add disrupt party at index 0
        })
        .collect()
}
