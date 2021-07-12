//! In this module we put all helper structs (and their implementations) that are used for keygen

use super::{proto::message_out::keygen_result, protocol::map_tofnd_to_tofn_idx};
use tofn::protocol::gg20::keygen::crimes::Crime;

/// wrapper type for proto::message_out::new_keygen_result
pub type KeygenResultData = Result<keygen_result::KeygenOutput, Vec<Vec<Crime>>>;

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
}

/// Context holds the all arguments that need to be passed from keygen gRPC call into protocol execution
pub struct Context {
    pub uids: Vec<String>,        // all party uids; alligned with `share_counts`
    pub share_counts: Vec<usize>, // all party share counts; alligned with `uids`
    pub threshold: usize,         // protocol's threshold
    pub tofnd_index: usize,       // tofnd index of party
    pub tofnd_subindex: usize,    // index of party's share
    pub nonce: String,            // session nonce; we use session's uid
}
impl Context {
    /// create a new Context
    pub fn new(
        keygen_init: &KeygenInitSanitized,
        tofnd_index: usize,
        tofnd_subindex: usize,
    ) -> Self {
        Context {
            uids: keygen_init.party_uids.clone(),
            share_counts: keygen_init.party_share_counts.clone(),
            threshold: keygen_init.threshold,
            tofnd_index,
            tofnd_subindex,
            nonce: keygen_init.new_key_uid.clone(),
        }
    }

    /// get party's tofn index based on `tofnd_index` and `tofnd_subindex`
    pub fn tofn_index(&self) -> usize {
        map_tofnd_to_tofn_idx(self.tofnd_index, self.tofnd_subindex, &self.share_counts)
    }

    /// get total number of shares of all parties
    pub fn total_share_count(&self) -> usize {
        self.share_counts.iter().sum()
    }

    /// return `nonce` field as bytes
    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_bytes()
    }

    /// print `Context`'s state; used for logging
    pub fn log_info(&self) -> String {
        format!(
            "[{}] [uid:{}, share:{}/{}]",
            self.nonce,
            self.uids[self.tofnd_index],
            self.tofnd_subindex + 1,
            self.total_share_count(),
        )
    }
}
