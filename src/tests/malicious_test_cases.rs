use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};

pub struct Signer {
    pub party_index: usize,
    pub behaviour: MaliciousType,
}

impl Signer {
    pub(super) fn new(party_index: usize, behaviour: MaliciousType) -> Self {
        Signer {
            party_index,
            behaviour,
        }
    }
}

pub struct TestCase {
    pub uid_count: usize,
    pub share_counts: Vec<u32>,
    pub threshold: usize,
    pub signer_indices: Vec<usize>,
    pub criminal_list: Vec<usize>,
    pub malicious_types: Vec<MaliciousType>, // TODO: include CrimeType = {Malicious, NonMalicious} in the future
}

impl TestCase {
    #[cfg(not(feature = "malicious"))]
    pub fn new(
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

    pub fn new(
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
        let mut criminal_list = Vec::new();
        for sign_participant in sign_participants.iter() {
            signer_indices.push(sign_participant.party_index);
            signer_behaviours.push(sign_participant.behaviour.clone());
            if !matches!(sign_participant.behaviour, Honest) {
                criminal_list.push(sign_participant.party_index);
            }
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

pub fn generate_test_cases() -> Vec<TestCase> {
    vec![
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 3],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, Honest),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R1BadProof { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R1FalseAccusation { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R2BadMta { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R2BadMtaWc { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R2FalseAccusationMta { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R2FalseAccusationMtaWc { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R3BadProof),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R3FalseAccusation { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R4BadReveal),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R4FalseAccusation { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R5BadProof { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R5FalseAccusation { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R6BadProof),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R6FalseAccusation { victim: 0 }),
        //     ],
        // ),
        // TestCase::new(
        //     4,
        //     vec![1, 1, 1, 1],
        //     3,
        //     vec![
        //         Signer::new(0, Honest),
        //         Signer::new(1, Honest),
        //         Signer::new(2, Honest),
        //         Signer::new(3, R7BadSigSummand),
        //     ],
        // ),
        TestCase::new(
            4,
            vec![1, 1, 1, 1],
            3,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, R1FalseAccusation { victim: 0 }),
                Signer::new(2, R1BadProof { victim: 0 }),
            ],
        ),
        TestCase::new(
            4,
            vec![1, 2, 1, 3],
            2,
            vec![
                Signer::new(0, Honest),
                Signer::new(1, R2BadMta { victim: 0 }),
                Signer::new(2, R2BadMtaWc { victim: 0 }),
            ],
        ),
        // TODO add more complex tests for malicious behaviours
    ]
}
