use crate::proto::message_out::{
    criminal_list::{criminal::CrimeType, Criminal},
    CriminalList,
};

use tofn::{
    collections::TypedUsize,
    gg20::sign::malicious::Behaviour::{self, *},
};

use super::super::{run_test_cases, TestCase};
use super::{Disrupt, MaliciousData, Timeout};

use tracing_test::traced_test; // log for tests

#[traced_test]
#[tokio::test(flavor = "multi_thread")]
async fn malicious_general_cases() {
    run_test_cases(&generate_basic_cases()).await;
}

// #[traced_test]
// #[tokio::test(flavor = "multi_thread")]
// async fn malicious_general_cases_with_restart() {
//     run_restart_test_cases(&generate_basic_cases()).await;
// }

#[traced_test]
#[tokio::test(flavor = "multi_thread")]
async fn malicious_timeout_cases() {
    run_test_cases(&timeout_cases()).await;
}

#[traced_test]
#[tokio::test(flavor = "multi_thread")]
async fn malicious_disrupt_cases() {
    run_test_cases(&disrupt_cases()).await;
}

pub(super) struct Signer {
    pub(super) party_index: usize,
    pub(super) behaviour: Behaviour,
}

impl Signer {
    pub(super) fn new(party_index: usize, behaviour: Behaviour) -> Self {
        Signer {
            party_index,
            behaviour,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SignData {
    pub(crate) behaviours: Vec<Behaviour>,
    pub(crate) timeout: Option<Timeout>,
    pub(crate) disrupt: Option<Disrupt>,
}

impl SignData {
    pub(crate) fn empty(party_count: usize) -> SignData {
        SignData {
            behaviours: vec![Honest; party_count],
            timeout: None,
            disrupt: None,
        }
    }
}

impl TestCase {
    fn new_malicious_sign(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        signers: Vec<Signer>,
    ) -> TestCase {
        let mut expected_faults = vec![];
        // TODO: enable this when sign faults are available
        for (i, signer) in signers.iter().enumerate() {
            if matches!(signer.behaviour, Behaviour::Honest) {
                continue;
            }
            expected_faults.push(Criminal {
                party_uid: ((b'A' + i as u8) as char).to_string(),
                crime_type: CrimeType::Malicious as i32,
            });
        }
        let expected_faults = CriminalList {
            criminals: expected_faults,
        };

        // we use the Signer struct to allign the beaviour type with the index of each signer
        // However, in the context of tofnd, behaviour is not only related with signers, but with
        // init_party, as well. That is, because we need to initialize a Gg20 service for both
        // signers and non-signers. We build these vectors from user's input `sign_participants`:
        // 1. behaviours -> holds the behaviour of every party (not just signers) and is alligned with tofnd party uids
        // 2. signer_indices -> holds the tofnd index of every signer
        let mut signer_indices = Vec::new();
        let mut signer_behaviours = Vec::new();

        for signer in signers.iter() {
            signer_indices.push(signer.party_index);
            signer_behaviours.push(signer.behaviour.clone());
        }

        let mut behaviours = Vec::new();
        for i in 0..uid_count {
            if !signer_indices.contains(&i) {
                behaviours.push(Honest);
            } else {
                let signer_index = signer_indices.iter().position(|&idx| idx == i).unwrap();
                let signer_type = signer_behaviours[signer_index].clone();
                behaviours.push(signer_type);
            }
        }

        let mut malicious_data = MaliciousData::empty(uid_count);
        malicious_data.set_sign_data(SignData {
            behaviours,
            timeout: None,
            disrupt: None,
        });

        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            expected_keygen_faults: CriminalList::default(),
            expected_sign_faults: expected_faults,
            malicious_data,
        }
    }

    fn with_sign_timeout(mut self, index: usize, round: usize) -> Self {
        let keygen_rounds = 4;
        self.malicious_data.sign_data.timeout = Some(Timeout {
            index,
            round: keygen_rounds + round,
        });
        self.expected_sign_faults = CriminalList {
            criminals: vec![Criminal {
                party_uid: ((b'A' + index as u8) as char).to_string(),
                crime_type: CrimeType::NonMalicious as i32,
            }],
        };
        self
    }

    fn with_sign_disrupt(mut self, index: usize, round: usize) -> Self {
        let keygen_rounds = 4;
        self.malicious_data.sign_data.disrupt = Some(Disrupt {
            index,
            round: round + keygen_rounds,
        });
        self.expected_sign_faults = CriminalList {
            criminals: vec![Criminal {
                party_uid: ((b'A' + index as u8) as char).to_string(),
                crime_type: CrimeType::NonMalicious as i32,
            }],
        };
        self
    }
}

fn generate_basic_cases() -> Vec<TestCase> {
    let victim = TypedUsize::from_usize(0);
    let behaviours = vec![
        R1BadProof { victim },
        R1BadGammaI,
        R2FalseAccusation { victim },
        R2BadMta { victim },
        R2BadMtaWc { victim },
        R3FalseAccusationMta { victim },
        R3FalseAccusationMtaWc { victim },
        R3BadProof,
        R3BadDeltaI,
        R3BadKI,
        R3BadAlpha { victim },
        R3BadBeta { victim },
        R4BadReveal,
        R5BadProof { victim },
        R6FalseAccusation { victim },
        R6BadProof,
        R6FalseType5Claim,
        R7BadSI,
        R7FalseType7Claim,
        R3BadSigmaI,
    ];

    behaviours
        .into_iter()
        .map(|b| {
            TestCase::new_malicious_sign(
                4,
                vec![1, 1, 1, 1],
                3,
                vec![
                    Signer::new(0, Honest),
                    Signer::new(1, Honest),
                    Signer::new(2, Honest),
                    Signer::new(3, b),
                ],
            )
        })
        .collect()
}

fn timeout_cases() -> Vec<TestCase> {
    // let timeout_rounds = vec![1];
    let timeout_rounds = vec![1, 2, 3, 4, 5, 6, 7];
    timeout_rounds
        .into_iter()
        .map(|r| {
            TestCase::new_malicious_sign(
                3,
                vec![1, 1, 1],
                2,
                vec![
                    Signer::new(0, Honest),
                    Signer::new(1, Honest),
                    Signer::new(2, Honest),
                ],
            )
            .with_sign_timeout(0, r) // add timeout party at _keygen_ index 0
        })
        .collect()
}

fn disrupt_cases() -> Vec<TestCase> {
    let disrupt_rounds = vec![1, 2, 3, 4, 5, 6, 7];
    disrupt_rounds
        .into_iter()
        .map(|r| {
            TestCase::new_malicious_sign(
                3,
                vec![1, 1, 1],
                2,
                vec![
                    Signer::new(0, Honest),
                    Signer::new(1, Honest),
                    Signer::new(2, Honest),
                ],
            )
            .with_sign_disrupt(0, r) // add disrupt party at _keygen_ index 0
        })
        .collect()
}
