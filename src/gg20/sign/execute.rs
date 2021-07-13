//! This module executes the keygen protocol
//! On success it returns [SignOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [TofndError] if [Keygen] cannot be instantiated.

use tofn::protocol::gg20::{
    sign::{malicious::BadSign, SignOutput},
    SecretKeyShare,
};

use super::{proto, protocol, Gg20Service, MessageDigest, ProtocolCommunication};
use crate::TofndError;

// logging
use tracing::{info, span, warn, Level, Span};

impl Gg20Service {
    // execute sign protocol and write the result into the internal channel
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_sign(
        &self,
        chan: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        party_uids: &[String],
        party_share_counts: &[usize],
        participant_tofn_indices: &[usize],
        secret_key_share: SecretKeyShare,
        message_to_sign: &MessageDigest,
        execute_span: Span,
    ) -> Result<SignOutput, TofndError> {
        // Sign::new() needs 'tofn' information:
        let mut sign = self.get_sign(
            &secret_key_share,
            &participant_tofn_indices,
            &message_to_sign,
        )?;

        let protocol_result = protocol::execute_protocol(
            &mut sign,
            chan,
            &party_uids,
            &party_share_counts,
            execute_span.clone(),
        )
        .await;

        Ok(Self::process_sign_result(
            sign,
            protocol_result,
            execute_span,
        )?)
    }

    // TODO: change here when bad sign does not exist
    fn process_sign_result(
        #[cfg(not(feature = "malicious"))] protocol_state: Sign,
        #[cfg(feature = "malicious")] protocol_state: BadSign,
        protocol_result: Result<(), TofndError>,
        execute_span: Span,
    ) -> Result<SignOutput, TofndError> {
        let result_span = span!(parent: &execute_span, Level::INFO, "result");
        let _enter = result_span.enter();

        let sign_result = match protocol_result {
            Ok(()) => {
                info!("Sign completed successfully");
                protocol_state
                    .clone_output()
                    .ok_or("sign output is `None`")?
            }
            // if protocol result was an error, check for disrupting parties
            Err(err) => match protocol_state.found_disrupting() {
                true => {
                    warn!("Party failed due to deserialization error: {}", err);
                    protocol_state
                        .clone_output()
                        .ok_or("sign output is `None`")?
                }
                // if no disrupting parties were found, return the waiting on parties
                false => {
                    let waiting_on = protocol_state.waiting_on();
                    warn!(
                        "Protocol ended prematurely: while I was waiting on {:?} {}",
                        waiting_on, err
                    );
                    Err(waiting_on)
                }
            },
        };

        // return result
        Ok(sign_result)
    }
}
