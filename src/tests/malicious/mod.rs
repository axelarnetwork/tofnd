pub mod keygen_test_cases;

use keygen_test_cases::KeygenData;
pub(super) type KeygenSpoof = keygen_test_cases::Spoof;
pub(super) type KeygenMsgMeta = keygen_test_cases::MsgMeta;
pub(super) type KeygenBehaviour = tofn::refactor::keygen::malicious::Behaviour;

// pub mod sign_test_cases;
// use sign_test_cases::SignData;
// pub(super) type SignSpoof = sign_test_cases::Spoof;
// pub(super) type SignMsgMeta = sign_test_cases::MsgMeta;
// pub(super) type SignBehaviour = tofn::protocol::gg20::sign::malicious::Behaviour;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum MsgType {
    KeygenMsgType {
        msg_type: tofn::protocol::gg20::keygen::MsgType,
    },
    SignMsgType {
        msg_type: tofn::protocol::gg20::sign::MsgType,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct Timeout {
    pub(crate) index: usize,
    pub(crate) round: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Disrupt {
    pub(crate) index: usize,
    pub(crate) msg_type: MsgType,
}

#[derive(Clone, Debug)]
pub(super) struct MaliciousData {
    pub(super) keygen_data: KeygenData,
    // pub(super) sign_data: SignData,
}

impl MaliciousData {
    pub(super) fn empty(party_count: usize) -> MaliciousData {
        MaliciousData {
            keygen_data: KeygenData::empty(party_count),
            // sign_data: SignData::empty(party_count),
        }
    }
    pub(super) fn set_keygen_data(&mut self, keygen_data: KeygenData) {
        self.keygen_data = keygen_data;
    }
    // pub(super) fn set_sign_data(&mut self, sign_data: SignData) {
    //     self.sign_data = sign_data;
    // }
}

#[derive(Clone, Debug)]
pub(crate) enum Spoof {
    KeygenSpoofType { spoof: KeygenSpoof },
    // SignSpoofType { spoof: SignSpoof },
}

#[derive(Clone, Debug)]
pub(super) struct PartyMaliciousData {
    pub(super) disrupt: Option<Disrupt>,
    pub(super) timeout_round: usize,
    pub(super) spoof: Option<Spoof>,
    pub(super) keygen_behaviour: KeygenBehaviour,
    // pub(super) sign_behaviour: SignBehaviour,
}
