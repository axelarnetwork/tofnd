//! This module creates and executes the sign protocol
//! On success it returns [SignOutput]. A successful [Sign] can produce either an Ok(Vec<u8>) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [TofndError] if [Sign] cannot be instantiated.

use super::{proto, protocol, types::Context, Gg20Service, ProtocolCommunication};
use crate::TofndError;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::BadSign;
#[cfg(not(feature = "malicious"))]
use tofn::protocol::gg20::sign::Sign;
use tofn::protocol::gg20::sign::SignOutput;

// logging
use tracing::{info, span, warn, Level, Span};

impl Gg20Service {
    /// create and execute sign protocol and returning the result.
    /// if the protocol cannot be instantiated, return a TofndError
    pub(super) async fn execute_sign(
        &self,
        chans: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        ctx: &Context,
        execute_span: Span,
    ) -> Result<SignOutput, TofndError> {
        // create sign with context
        // TODO: change sign here when new constructor is available
        let mut sign = self.get_sign(
            &ctx.secret_key_share,
            &ctx.sign_tofn_indices(),
            &ctx.msg_to_sign(),
        )?;

        // execute protocol and wait for completion
        let protocol_result = protocol::execute_protocol(
            &mut sign,
            chans,
            &ctx.sign_uids(),
            &ctx.sign_share_counts,
            execute_span.clone(),
        )
        .await;

        // return processed result
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
