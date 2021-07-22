pub mod keygen_test_cases;
use keygen_test_cases::KeygenData;
pub(super) type KeygenBehaviour = tofn::refactor::keygen::malicious::Behaviour;

pub mod sign_test_cases;
use sign_test_cases::SignData;
pub(super) type SignBehaviour = tofn::refactor::sign::malicious::Behaviour;

#[derive(Clone, Debug)]
pub(crate) struct Timeout {
    pub(crate) index: usize,
    pub(crate) round: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Disrupt {
    pub(crate) index: usize,
    pub(crate) round: usize,
}

#[derive(Clone, Debug)]
pub(super) struct MaliciousData {
    pub(super) keygen_data: KeygenData,
    pub(super) sign_data: SignData,
}

impl MaliciousData {
    pub(super) fn empty(party_count: usize) -> MaliciousData {
        MaliciousData {
            keygen_data: KeygenData::empty(party_count),
            sign_data: SignData::empty(party_count),
        }
    }
    pub(super) fn set_keygen_data(&mut self, keygen_data: KeygenData) {
        self.keygen_data = keygen_data;
    }
    pub(super) fn set_sign_data(&mut self, sign_data: SignData) {
        self.sign_data = sign_data;
    }
}

#[derive(Clone, Debug)]
pub(super) struct PartyMaliciousData {
    pub(super) timeout_round: usize,
    pub(super) disrupt_round: usize,
    pub(super) keygen_behaviour: KeygenBehaviour,
    pub(super) sign_behaviour: SignBehaviour,
}
