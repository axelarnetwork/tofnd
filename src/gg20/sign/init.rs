use std::convert::TryInto;

use super::{proto, types::SignInitSanitized, Gg20Service, PartyInfo};
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::Status;

use tracing::{error, info, span, Level, Span};

impl Gg20Service {
    // makes all needed assertions on incoming data, and create structures that are
    // needed to execute the protocol
    pub(super) async fn handle_sign_init(
        &mut self,
        in_stream: &mut tonic::Streaming<proto::MessageIn>,
        mut out_stream: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        sign_span: Span,
    ) -> Result<(SignInitSanitized, PartyInfo), TofndError> {
        let msg_type = in_stream
            .next()
            .await
            .ok_or("sign: stream closed by client without sending a message")??
            .data
            .ok_or("sign: missing `data` field in client message")?;

        let sign_init = match msg_type {
            proto::message_in::Data::SignInit(k) => k,
            _ => return Err(From::from("Expected sign init message")),
        };

        let party_info = self.shares_kv.get(&sign_init.key_uid).await;
        let party_info = match party_info {
            Ok(party_info) => party_info,
            Err(err) => {
                error!("Unable to find session-id {} in kv store. Issuing share recovery and exit sign {:?}", sign_init.key_uid, err);
                Self::send_kv_store_failure(&sign_init.key_uid, &mut out_stream)?;
                return Err(err);
            }
        };

        let sign_init = Self::sign_sanitize_args(sign_init, &party_info.tofnd.party_uids)?;

        // log SignInitSanitized state
        party_info.log_info(&sign_init.new_sig_uid, sign_span);

        Ok((sign_init, party_info))
    }

    // sanitize arguments of incoming message.
    // Example:
    // input for party 'a':
    //   (from keygen) party_uids = [a, b, c]
    //   (from keygen) party_share_counts = [3, 2, 1]
    //   proto::SignInit.party_uids = [c, a]
    // output for party 'a':
    //   SignInitSanitized.party_uids = [2, 0]  <- index of c, a in party_uids
    fn sign_sanitize_args(
        sign_init: proto::SignInit,
        all_party_uids: &[String],
    ) -> Result<SignInitSanitized, TofndError> {
        // create a vector of the tofnd indices of the participant uids
        let participant_indices = sign_init
            .party_uids
            .iter()
            .map(|s| {
                all_party_uids.iter().position(|k| k == s).ok_or(format!(
                    "participant [{}] not found in key [{}]",
                    s, sign_init.key_uid
                ))
            })
            .collect::<Result<Vec<usize>, _>>()?;

        Ok(SignInitSanitized {
            new_sig_uid: sign_init.new_sig_uid,
            participant_uids: sign_init.party_uids,
            participant_indices,
            message_to_sign: sign_init.message_to_sign.as_slice().try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_sign_sanitize_args() {
        let all_party_uids = vec![
            "party_0".to_owned(), // party 0 has index 0
            "party_1".to_owned(), // party 1 has index 1
            "party_2".to_owned(), // party 2 has index 2
        ];

        let raw_sign_init = proto::SignInit {
            new_sig_uid: "test_uid".to_owned(),
            key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_2".to_owned(), "party_1".to_owned()],
            message_to_sign: vec![42; 32],
        };
        let sanitized_sign_init = SignInitSanitized {
            new_sig_uid: "test_uid".to_owned(), // new sig uid should be the same
            participant_uids: vec!["party_2".to_owned(), "party_1".to_owned()], // party 2 has index 2, party 1 has index 1
            participant_indices: vec![2, 1], // indices should be [2, 1]
            message_to_sign: vec![42; 32].as_slice().try_into().unwrap(), // msg of 32 bytes should be successfully converted to MessageDigest
        };

        let res = Gg20Service::sign_sanitize_args(raw_sign_init, &all_party_uids).unwrap();
        assert_eq!(&res.new_sig_uid, &sanitized_sign_init.new_sig_uid);
        assert_eq!(&res.participant_uids, &sanitized_sign_init.participant_uids);
        assert_eq!(
            &res.participant_indices,
            &sanitized_sign_init.participant_indices
        );
        assert_eq!(&res.message_to_sign, &sanitized_sign_init.message_to_sign);
    }

    #[test]
    fn test_fail_sign_sanitize_args() {
        let all_party_uids = vec![
            "party_0".to_owned(),
            "party_1".to_owned(),
            "party_2".to_owned(),
        ];
        let raw_sign_init = proto::SignInit {
            new_sig_uid: "test_uid".to_owned(),
            key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_4".to_owned(), "party_1".to_owned()], // party 4 does not exist
            message_to_sign: vec![42; 32],
        };
        assert!(Gg20Service::sign_sanitize_args(raw_sign_init, &all_party_uids).is_err());

        let raw_sign_init = proto::SignInit {
            new_sig_uid: "test_uid".to_owned(),
            key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_2".to_owned(), "party_1".to_owned()],
            message_to_sign: vec![42; 33], // message is not 32 bytes
        };
        assert!(Gg20Service::sign_sanitize_args(raw_sign_init, &all_party_uids).is_err());
    }
}
