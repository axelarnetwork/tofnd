//! Helper structs and implementations for [crate::gg20::keygen].

use crate::TofndError;

use tofn::{
    collections::TypedUsize,
    gg20::keygen::{
        KeygenPartyId, KeygenPartyShareCounts, PartyKeyPair, PartyZkSetup, SecretKeyShare,
    },
    sdk::api::ProtocolOutput,
};

pub(super) type PartyShareCounts = KeygenPartyShareCounts;
pub const MAX_PARTY_SHARE_COUNT: usize = tofn::gg20::keygen::MAX_PARTY_SHARE_COUNT;
pub const MAX_TOTAL_SHARE_COUNT: usize = tofn::gg20::keygen::MAX_TOTAL_SHARE_COUNT;

use tracing::{info, span, Level, Span};

/// tofn's ProtocolOutput for Keygen
pub type TofnKeygenOutput = ProtocolOutput<SecretKeyShare, KeygenPartyId>;
/// tofnd's ProtocolOutput for Keygen
pub type TofndKeygenOutput = Result<TofnKeygenOutput, TofndError>;
/// type for bytes
pub type Bytes = Vec<u8>;

/// KeygenInitSanitized holds all arguments needed by Keygen in the desired form; populated by proto::KeygenInit
/// pub because it is also needed by recovery module
pub struct KeygenInitSanitized {
    pub new_key_uid: String,            // session's UID
    pub party_uids: Vec<String>, // vector of party uids; this is alligned with party_share_count vector
    pub party_share_counts: Vec<usize>, // vector of share counts; this is alligned with party_uids vector
    pub my_index: usize, // the _tofnd_ index of the party inside party_uids and party_shares_counts
    pub threshold: usize, // protocol's threshold
}
impl KeygenInitSanitized {
    // get the share count of `my_index`th party
    pub(super) fn my_shares_count(&self) -> usize {
        self.party_share_counts[self.my_index] as usize
    }

    // log KeygenInitSanitized state
    pub(super) fn log_info(&self, keygen_span: Span) {
        // create log span and display current status
        let init_span = span!(parent: &keygen_span, Level::INFO, "init");
        let _enter = init_span.enter();
        info!(
            "[uid:{}, shares:{}] starting Keygen with [key: {}, (t,n)=({},{}), participants:{:?}",
            self.party_uids[self.my_index],
            self.my_shares_count(),
            self.new_key_uid,
            self.threshold,
            self.party_share_counts.iter().sum::<usize>(),
            self.party_uids,
        );
    }
}

/// Context holds the all arguments that need to be passed from keygen gRPC call into protocol execution
pub struct Context {
    pub(super) key_id: String,           // session id; used for logs
    pub(super) uids: Vec<String>,        // all party uids; alligned with `share_counts`
    pub(super) share_counts: Vec<usize>, // all party share counts; alligned with `uids`
    pub(super) threshold: usize,         // protocol's threshold
    pub(super) tofnd_index: TypedUsize<KeygenPartyId>, // tofnd index of party
    pub(super) tofnd_subindex: usize,    // index of party's share
    pub(super) party_keypair: PartyKeyPair,
    pub(super) party_zksetup: PartyZkSetup,
}

impl Context {
    /// create a new Context
    pub fn new(
        keygen_init: &KeygenInitSanitized,
        tofnd_index: usize,
        tofnd_subindex: usize,
        party_keypair: PartyKeyPair,
        party_zksetup: PartyZkSetup,
    ) -> Self {
        let tofnd_index = TypedUsize::from_usize(tofnd_index);
        Context {
            key_id: keygen_init.new_key_uid.clone(),
            uids: keygen_init.party_uids.clone(),
            share_counts: keygen_init.party_share_counts.clone(),
            threshold: keygen_init.threshold,
            tofnd_index,
            tofnd_subindex,
            party_keypair,
            party_zksetup,
        }
    }

    /// get share_counts in the form of tofn::PartyShareCounts
    pub fn share_counts(&self) -> Result<PartyShareCounts, TofndError> {
        match PartyShareCounts::from_vec(self.share_counts.clone()) {
            Ok(party_share_counts) => Ok(party_share_counts),
            Err(_) => Err(From::from("failed to create party_share_counts")),
        }
    }

    /// export state; used for logging
    pub fn log_info(&self) -> String {
        format!(
            "[{}] [uid:{}, share:{}/{}]",
            self.key_id,
            self.uids[self.tofnd_index.as_usize()],
            self.tofnd_subindex + 1,
            self.share_counts[self.tofnd_index.as_usize()]
        )
    }
}
