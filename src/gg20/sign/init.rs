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

        let init_span = span!(parent: &sign_span, Level::INFO, "init");
        let _enter = init_span.enter();

        info!(
            "[uid:{}, shares:{}] starting Sign with [key: {}, (t,n)=({},{}), participants:{:?}",
            party_info.tofnd.party_uids[party_info.tofnd.index],
            party_info.tofnd.share_counts[party_info.tofnd.index],
            sign_init.new_sig_uid,
            party_info.common.threshold(),
            party_info.tofnd.share_counts.iter().sum::<usize>(),
            party_info.tofnd.party_uids,
        );

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
