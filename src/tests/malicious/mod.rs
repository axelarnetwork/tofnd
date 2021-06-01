pub mod keygen_test_cases;
pub mod sign_test_cases;

use keygen_test_cases::KeygenData;
use sign_test_cases::SignData;

pub(super) type SignSpoof = sign_test_cases::Spoof;
pub(super) type SignTimeout = sign_test_cases::Timeout;
pub(super) type SignMsgMeta = sign_test_cases::MsgMeta;
pub(super) type KeygenBehaviour = tofn::protocol::gg20::keygen::malicious::Behaviour;
pub(super) type SignBehaviour = tofn::protocol::gg20::sign::malicious::MaliciousType;

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
    pub(super) timeout: Option<SignTimeout>,
    pub(super) spoof: Option<SignSpoof>,
    pub(super) keygen_malicious_type: KeygenBehaviour,
    pub(super) sign_malicious_type: SignBehaviour,
}
