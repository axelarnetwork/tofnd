use strum::IntoEnumIterator;
use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};
use tofn::protocol::gg20::sign::{crimes::Crime, MsgType};

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

pub(super) struct TestCase {
    pub(super) uid_count: usize,
    pub(super) share_counts: Vec<u32>,
    pub(super) threshold: usize,
    pub(super) signer_indices: Vec<usize>,
    pub(super) malicious_types: Vec<MaliciousType>,
    pub(super) expected_crimes: Vec<Vec<Crime>>,
    pub(super) timeout: Option<Timeout>,
}

#[derive(Clone, Debug)]
pub(super) struct Timeout {
    pub(super) index: usize,
    pub(super) msg_type: MsgType,
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

        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            malicious_types,
            expected_crimes,
            timeout,
        }
    }
}

pub(super) fn generate_test_cases() -> Vec<TestCase> {
    let mut test_cases: Vec<TestCase> = Vec::new();
    test_cases.extend(generate_basic_cases());
    test_cases.extend(generate_multiple_malicious_per_round());
    test_cases.extend(timeout_cases());
    test_cases
}

pub(super) fn timeout_cases() -> Vec<TestCase> {
    let t = MaliciousType::Staller {
        msg_type: tofn::protocol::gg20::sign::MsgType::R1Bcast,
    };
    vec![TestCase::new(
        4,
        vec![1, 1, 1, 1],
        3,
        vec![
            Signer::new(0, t.clone(), map_type_to_crime(&t)),
            Signer::new(1, Honest, vec![]),
            Signer::new(2, Honest, vec![]),
            Signer::new(3, Honest, vec![]),
        ],
    )]
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
