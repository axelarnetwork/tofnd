//! Helper structs and implementations for [crate::gg20::sign].

use super::super::MessageDigest;
use tofn::collections::{Subset, TypedUsize};
use tofn::gg20::keygen::{GroupPublicInfo, RealKeygenPartyIndex, ShareSecretInfo};
use tofn::gg20::sign::{RealSignParticipantIndex, SignParties};
use tofn::sdk::api::ProtocolOutput;

/// tofn's ProtocolOutput for Sign
pub type TofnSignOutput = ProtocolOutput<Vec<u8>, RealSignParticipantIndex>;
/// tofnd's ProtocolOutput for Sign
pub type TofndSignOutput = Result<TofnSignOutput, TofndError>;

#[derive(Clone, Debug)]
pub(super) struct SignInitSanitized {
    pub(super) new_sig_uid: String, // this is only used for logging
    // pub(super) key_uid: String,
    pub(super) participant_uids: Vec<String>,
    pub(super) participant_indices: Vec<usize>,
    pub(super) message_to_sign: MessageDigest,
}

use crate::gg20::types::PartyInfo;
use crate::TofndError;

pub(super) struct Context {
    pub(super) sign_init: SignInitSanitized,
    pub(super) party_info: PartyInfo,
    pub(super) sign_share_counts: Vec<usize>,
    pub(super) tofnd_subindex: usize,
    pub(super) share: ShareSecretInfo,
    pub(super) sign_parties: Subset<RealKeygenPartyIndex>,
}

impl Context {
    /// create a new signing context
    pub(super) fn new(
        sign_init: SignInitSanitized,
        party_info: PartyInfo,
        tofnd_subindex: usize,
    ) -> Result<Self, TofndError> {
        // retrieve sign_share_couts and secret_key_shares here instead of adding
        // getters to immediatelly dicover potential errors
        let sign_share_counts = Self::get_sign_share_counts(
            &party_info.tofnd.party_uids,
            &party_info.tofnd.share_counts,
            &sign_init.participant_uids,
        )?;

        let sign_parties = Self::get_sign_parties(
            party_info.tofnd.party_uids.len(),
            &sign_init.participant_indices,
        )?;

        let share = Self::get_share(&party_info, tofnd_subindex)?;
        Ok(Self {
            sign_init,
            party_info,
            sign_share_counts,
            tofnd_subindex,
            share,
            sign_parties,
        })
    }

    pub(super) fn group(&self) -> &GroupPublicInfo {
        &self.party_info.common
    }

    /// from keygen we have
    ///  party uids:         [A, B, C, D]
    ///  share counts:       [1, 2, 3, 4]
    /// in sign we receive
    ///  sign uids:          [D, B]
    /// we need to construct an array of share counts that is alligned with sign uids
    ///  sign share counts:  [4, 2]
    fn get_sign_share_counts(
        keygen_uids: &[String],
        keygen_share_counts: &[usize],
        sign_uids: &[String],
    ) -> Result<Vec<usize>, TofndError> {
        if keygen_uids.len() != keygen_share_counts.len() {
            return Err(From::from(
                "misalligned keygen uids and keygen share counts",
            ));
        }
        let mut sign_share_counts = vec![];
        for sign_uid in sign_uids {
            let keygen_index = keygen_uids
                .iter()
                .position(|uid| uid == sign_uid)
                .ok_or("Sign uid was not found")?;
            let sign_share_count = *keygen_share_counts
                .get(keygen_index)
                .ok_or("invalid index")?;
            sign_share_counts.push(sign_share_count);
        }
        Ok(sign_share_counts)
    }

    fn get_share(
        party_info: &PartyInfo,
        tofnd_subindex: usize,
    ) -> Result<ShareSecretInfo, TofndError> {
        Ok(party_info
            .shares
            .get(tofnd_subindex)
            .ok_or("failed to get ShareSecretInfo from PartyInfo")?
            .clone())
    }

    pub(super) fn msg_to_sign(&self) -> &MessageDigest {
        &self.sign_init.message_to_sign
    }

    /// create a `Subset` of sign parties
    /// Example:
    /// from keygen init we have:
    ///   keygen_party_uids:    [a, b, c, d]
    ///   keygen_party_indices: [0, 1, 2, 3]
    /// from sign init we have:
    ///   sign_party_uids:      [d, b]
    ///   sign_party_indices:   [3, 1]
    /// result:
    ///   sign_parties:         [None      -> party a with index 0 is not a signer
    ///                          Some(())  -> party b with index 1 is a signer
    ///                          None      -> party c with index 2 is not a signer
    ///                          Some(())] -> party d with index 3 is a signer
    pub(super) fn get_sign_parties(
        length: usize,
        sign_indices: &[usize],
    ) -> Result<SignParties, TofndError> {
        let mut sign_parties = Subset::with_max_size(length);
        for signer_idx in sign_indices.iter() {
            if sign_parties
                .add(TypedUsize::from_usize(*signer_idx))
                .is_err()
            {
                return Err(From::from("failed to call Subset::add"));
            }
        }
        Ok(sign_parties)
    }

    /// get signers' uids with respect to keygen uids ordering
    /// Example:
    /// from keygen init we have:
    ///   keygen_party_uids:    [a, b, c, d]
    /// from sign init we have:
    ///   sign_party_uids:      [d, c, a]
    /// result:
    ///   sign_parties:         [a, c, d]
    pub(super) fn sign_uids(&self) -> Vec<String> {
        let mut sign_uids = vec![];
        for uid in self.party_info.tofnd.party_uids.iter() {
            if self
                .sign_init
                .participant_uids
                .iter()
                .any(|s_uid| s_uid == uid)
            {
                sign_uids.push(uid.clone());
            }
        }
        sign_uids
    }

    /// export state; used for logging
    pub(super) fn log_info(&self) -> String {
        format!(
            "[{}] [uid:{}, share:{}/{}]",
            self.sign_init.new_sig_uid,
            self.party_info.tofnd.party_uids[self.party_info.tofnd.index],
            self.party_info.shares[self.tofnd_subindex]
                .index()
                .as_usize()
                + 1,
            self.party_info.common.share_count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_parties() {}

    #[test]
    fn test_sign_share_counts() {
        struct TestCase {
            keygen_uids: Vec<String>,
            keygen_share_counts: Vec<usize>,
            sign_uids: Vec<String>,
            result: Vec<usize>,
        }

        let ok_test_cases = vec![
            TestCase {
                keygen_uids: vec!["a".to_owned(), "b".to_owned()],
                keygen_share_counts: vec![1, 2],
                sign_uids: vec!["a".to_owned(), "b".to_owned()],
                result: vec![1, 2],
            },
            TestCase {
                keygen_uids: vec!["b".to_owned(), "a".to_owned()],
                keygen_share_counts: vec![1, 2],
                sign_uids: vec!["a".to_owned()],
                result: vec![2],
            },
        ];

        let fail_test_cases = vec![
            TestCase {
                keygen_uids: vec!["a".to_owned(), "b".to_owned()],
                keygen_share_counts: vec![1, 2],
                sign_uids: vec!["c".to_owned()], // party "c" does not exist
                result: vec![],
            },
            TestCase {
                keygen_uids: vec!["a".to_owned(), "b".to_owned()],
                keygen_share_counts: vec![1, 2, 3], // keygen shares not alligned with uids
                sign_uids: vec!["a".to_owned()],
                result: vec![],
            },
        ];

        for t in ok_test_cases {
            let res = Context::get_sign_share_counts(
                &t.keygen_uids,
                &t.keygen_share_counts,
                &t.sign_uids,
            );
            assert_eq!(res.unwrap(), t.result);
        }
        for t in fail_test_cases {
            let res = Context::get_sign_share_counts(
                &t.keygen_uids,
                &t.keygen_share_counts,
                &t.sign_uids,
            );
            assert!(res.is_err());
        }
    }
}
