use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};

pub(super) struct Signer {
    pub(super) party_index: usize,
    pub(super) behaviour: MaliciousType,
}

impl Signer {
    pub(super) fn new(party_index: usize, behaviour: MaliciousType) -> Self {
        Signer {
            party_index,
            behaviour,
        }
    }
}

pub(super) struct TestCase {
    pub(super) uid_count: usize,
    pub(super) share_counts: Vec<u32>,
    pub(super) threshold: usize,
    pub(super) signer_indices: Vec<usize>,
    pub(super) criminal_list: Vec<usize>,
    pub(super) malicious_types: Vec<MaliciousType>, // TODO: include CrimeType = {Malicious, NonMalicious} in the future
}

impl TestCase {
    #[cfg(not(feature = "malicious"))]
    pub(super) fn new(
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

    pub(super) fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        sign_participants: Vec<Signer>,
        criminal_list: Vec<usize>,
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

        // could be more rusty but take double the LoC
        for sign_participant in sign_participants.iter() {
            signer_indices.push(sign_participant.party_index);
            signer_behaviours.push(sign_participant.behaviour.clone());
        }

        let mut malicious_types = Vec::new();
        for i in 0..uid_count {
            if !signer_indices.contains(&i) {
                malicious_types.push(Honest);
            } else {
                let signer_index = signer_indices.iter().position(|&idx| idx == i).unwrap();
                malicious_types.push(signer_behaviours[signer_index].clone());
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

pub(super) fn generate_test_cases() -> Vec<TestCase> {
    let mut test_cases: Vec<TestCase> = Vec::new();
    test_cases.extend(generate_simple_test_cases());
    test_cases.extend(generate_multiple_malicious_per_round());
    test_cases.extend(generate_with_stable_tofnd_indices());
    test_cases
}

pub(super) fn generate_simple_test_cases() -> Vec<TestCase> {
    vec![
        TestCase::new(
            4,
            vec![1, 1, 1, 3],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
            ],
            vec![],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R1BadProof { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R1FalseAccusation { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R2BadMta { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R2BadMtaWc { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R2FalseAccusationMta { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R2FalseAccusationMtaWc { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R3BadProof),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R3FalseAccusation { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R4BadReveal),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R4FalseAccusation { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R5BadProof { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R5FalseAccusation { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R6BadProof),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R6FalseAccusation { victim: 0 }),
            ],
            vec![3],
        ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, R7BadSigSummand),
            ],
            vec![3],
        ),
    ]
}

pub(super) fn generate_multiple_malicious_per_round() -> Vec<TestCase> {
    vec![
        TestCase::new(
            4,
            vec![1, 2, 1, 3],
            2,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, R1BadProof { victim: 0 }),
                Signer::new(2, R1FalseAccusation { victim: 0 }),
            ],
            vec![1, 2],
        ),
        TestCase::new(
            5,
            vec![1, 2, 1, 3, 2],
            6,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, R2BadMta { victim: 0 }),
                Signer::new(2, R2BadMtaWc { victim: 0 }),
                Signer::new(3, R2FalseAccusationMta { victim: 0 }),
                Signer::new(4, R2FalseAccusationMtaWc { victim: 0 }),
            ],
            vec![1, 2, 3, 4],
        ),
        TestCase::new(
            5,
            vec![4, 1, 1, 1, 1],
            6,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, R2BadMta { victim: 0 }),
                Signer::new(2, R2BadMtaWc { victim: 1 }),
                Signer::new(3, R2FalseAccusationMta { victim: 2 }),
                Signer::new(4, R2FalseAccusationMtaWc { victim: 3 }),
            ],
            vec![1, 2, 3, 4],
        ),
        TestCase::new(
            8,
            vec![1, 1, 1, 1, 1, 1, 1, 2],
            7,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R2BadMta { victim: 0 }),
                Signer::new(5, R2BadMtaWc { victim: 1 }),
                Signer::new(6, R2FalseAccusationMta { victim: 2 }),
                Signer::new(7, R2FalseAccusationMtaWc { victim: 3 }),
            ],
            vec![4, 5, 6, 7],
        ),
        TestCase::new(
            8,
            vec![1, 1, 1, 1, 1, 1, 1, 2],
            7,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R2BadMta { victim: 0 }),
                Signer::new(5, R2BadMtaWc { victim: 1 }),
                Signer::new(6, R3BadProof),
                Signer::new(7, R4BadReveal),
            ],
            vec![4, 5],
        ),
        TestCase::new(
            5,
            vec![1, 2, 1, 3, 2],
            3,
            vec![
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R1BadProof { victim: 0 }),
            ],
            vec![4],
        ),
    ]
}

pub(super) fn generate_with_stable_tofnd_indices() -> Vec<TestCase> {
    vec![
        TestCase::new(
            5,
            vec![2, 1, 1, 1, 2],
            4,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R2BadMta { victim: 0 }),
            ],
            vec![4],
        ),
        TestCase::new(
            5,
            vec![1, 2, 1, 1, 2],
            4,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R2BadMta { victim: 0 }),
            ],
            vec![4],
        ),
        TestCase::new(
            5,
            vec![1, 1, 2, 1, 2],
            4,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, Honest),
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R2BadMta { victim: 0 }),
            ],
            vec![4],
        ),
        TestCase::new(
            5,
            vec![1, 1, 1, 2, 2],
            2,
            vec![
                Signer::new(2, Honest),
                Signer::new(3, Honest),
                Signer::new(4, R2BadMta { victim: 0 }),
            ],
            vec![4],
        ),
    ]
}
