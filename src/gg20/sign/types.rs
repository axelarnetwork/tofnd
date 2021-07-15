use tofn::protocol::gg20::SecretKeyShare;

use super::MessageDigest;
#[derive(Clone, Debug)]
pub(super) struct SignInitSanitized {
    pub(super) new_sig_uid: String, // this is only used for logging
    // pub(super) key_uid: String,
    pub(super) participant_uids: Vec<String>,
    pub(super) participant_indices: Vec<usize>,
    pub(super) message_to_sign: MessageDigest,
}

use crate::gg20::{protocol::map_tofnd_to_tofn_idx, types::PartyInfo};
use crate::TofndError;

pub(super) struct Context {
    pub(super) sign_init: SignInitSanitized,
    pub(super) party_info: PartyInfo,
    pub(super) sign_share_counts: Vec<usize>,
    pub(super) tofnd_subindex: usize,
    pub(super) secret_key_share: SecretKeyShare,
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
        let secret_key_share = Self::get_secret_key_share(&party_info, tofnd_subindex)?;
        Ok(Self {
            sign_init,
            party_info,
            sign_share_counts,
            tofnd_subindex,
            secret_key_share,
        })
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

    fn get_secret_key_share(
        party_info: &PartyInfo,
        tofnd_subindex: usize,
    ) -> Result<SecretKeyShare, TofndError> {
        if tofnd_subindex >= party_info.shares.len() {
            return Err(From::from(format!(
                "Requested share {} is out of bounds {}",
                tofnd_subindex,
                party_info.shares.len(),
            )));
        }
        Ok(SecretKeyShare {
            group: party_info.common.clone(),
            share: party_info.shares[tofnd_subindex].clone(),
        })
    }

    pub(super) fn sign_uids(&self) -> &[String] {
        &self.sign_init.participant_uids
    }

    pub(super) fn msg_to_sign(&self) -> &MessageDigest {
        &self.sign_init.message_to_sign
    }

    pub(super) fn sign_tofn_indices(&self) -> Vec<usize> {
        // use stateless implementation function to ease tests
        Self::sign_tofn_indices_impl(
            &self.party_info.tofnd.share_counts,
            &self.sign_init.participant_indices,
        )
    }

    /// get all tofn indices of a party
    /// Example:
    /// input:
    ///   sign_uids = [a, c]
    ///   share_counts = [3, 2, 1]
    /// output:
    ///   all_party_tofn_indices: [0, 1, 2, 3, 4, 5]
    ///                            ^  ^  ^  ^  ^  ^
    ///                            a  a  a  b  b  c
    ///   signing_tofn_indices: [0, 1, 2, 5] <- index of a's 3 shares + c's 2 shares
    fn sign_tofn_indices_impl(sign_share_counts: &[usize], sign_indices: &[usize]) -> Vec<usize> {
        let mut sign_tofn_indices = Vec::new();
        for sign_index in sign_indices.iter() {
            let tofn_index = map_tofnd_to_tofn_idx(*sign_index, 0, &sign_share_counts);
            for share_count in 0..sign_share_counts[*sign_index] {
                sign_tofn_indices.push(tofn_index + share_count);
            }
        }
        sign_tofn_indices
    }

    /// export state; used for logging
    pub(super) fn log_info(&self) -> String {
        format!(
            "[{}] [uid:{}, share:{}/{}]",
            self.sign_init.new_sig_uid,
            self.party_info.tofnd.party_uids[self.party_info.tofnd.index],
            self.party_info.shares[self.tofnd_subindex].index() + 1,
            self.party_info.common.share_count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tofn_indices() {
        struct TestCase {
            share_counts: Vec<usize>,
            signing_indices: Vec<usize>,
            result: Vec<usize>,
        }

        let test_cases = vec![
            TestCase {
                share_counts: vec![1, 1, 1, 1],
                signing_indices: vec![0, 2],
                result: vec![0, 2],
            },
            TestCase {
                share_counts: vec![1, 1, 1, 2],
                signing_indices: vec![0, 3],
                result: vec![0, 3, 4],
            },
            TestCase {
                share_counts: vec![2, 1, 4, 1],
                signing_indices: vec![0, 2],
                result: vec![0, 1, 3, 4, 5, 6],
            },
        ];

        for t in test_cases {
            assert_eq!(
                Context::sign_tofn_indices_impl(&t.share_counts, &t.signing_indices),
                t.result
            );
        }
    }

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