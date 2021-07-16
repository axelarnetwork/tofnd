//! This module creates and executes the keygen protocol
//! On success it returns [KeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [TofndError] if [Keygen] struct cannot be instantiated.

use super::{proto, protocol, types::Context, Gg20Service, ProtocolCommunication};
use crate::TofndError;
use tofn::protocol::gg20::keygen::{Keygen, KeygenOutput};

// logging
use tracing::{info, span, warn, Level, Span};

impl Gg20Service {
    /// create and execute keygen protocol and returning the result.
    /// if the protocol cannot be instantiated, return a TofndError
    pub(super) async fn execute_keygen(
        &self,
        chans: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        ctx: &Context,
        execute_span: Span,
    ) -> Result<KeygenOutput, TofndError> {
        // create keygen with context
        let mut keygen = Keygen::new(
            ctx.total_share_count(),
            ctx.threshold,
            ctx.tofn_index(),
            &self.seed().await?,
            &ctx.nonce(),
        )?;
        // set up behaviour if we run in malicious mode
        #[cfg(feature = "malicious")]
        keygen.set_behaviour(self.keygen_behaviour.clone());

        // execute protocol and wait for completion
        let protocol_result = protocol::execute_protocol(
            &mut keygen,
            chans,
            &ctx.uids,
            &ctx.share_counts,
            execute_span.clone(),
        )
        .await;

        // return processed result
        Ok(Self::process_keygen_result(
            keygen,
            protocol_result,
            execute_span.clone(),
        )?)
    }

    /// constructs response from given protocol's state and result
    fn process_keygen_result(
        protocol_state: Keygen,
        protocol_result: Result<(), TofndError>,
        execute_span: Span,
    ) -> Result<KeygenOutput, TofndError> {
        let result_span = span!(parent: &execute_span, Level::INFO, "result");
        let _enter = result_span.enter();

        let keygen_output = match protocol_result {
            // if protocol result is ok, return keygen output
            Ok(()) => {
                info!("Keygen completed successfully");
                protocol_state
                    .clone_output()
                    .ok_or("keygen output is `None`")?
            }
            // if protocol result was an error, check for disrupting parties
            Err(err) => match protocol_state.found_disrupting() {
                // if disrupting parties were found, return keygen output
                true => {
                    warn!("Party failed due to deserialization error: {}", err);
                    protocol_state
                        .clone_output()
                        .ok_or("keygen output is `None`")?
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
        Ok(keygen_output)
    }
}
