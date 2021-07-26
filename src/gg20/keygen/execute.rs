//! This module creates and executes the keygen protocol
//! On success it returns [super::TofnKeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [super::TofndError] if [Keygen] struct cannot be instantiated.

use super::{
    proto,
    types::{Context, PartyShareCounts, TofndKeygenOutput},
    Gg20Service, ProtocolCommunication,
};

use tofn::{
    gg20::keygen::{new_keygen, new_keygen_unsafe, KeygenProtocol},
    sdk::api::TofnResult,
};

use crate::gg20::protocol;

// logging
use tracing::{info, Span};

impl Gg20Service {
    // allow for users to select whether to use big primes or not
    async fn new_keygen(
        &self,
        party_share_counts: PartyShareCounts,
        ctx: &Context,
    ) -> TofnResult<KeygenProtocol> {
        match self.safe_keygen {
            true => new_keygen(
                party_share_counts,
                ctx.threshold,
                ctx.tofnd_index,
                ctx.tofnd_subindex,
                &self.seed().await.unwrap(),
                &ctx.nonce(),
                #[cfg(feature = "malicious")]
                self.keygen_behaviour.clone(),
            ),
            false => new_keygen_unsafe(
                party_share_counts,
                ctx.threshold,
                ctx.tofnd_index,
                ctx.tofnd_subindex,
                &self.seed().await.unwrap(),
                &ctx.nonce(),
                #[cfg(feature = "malicious")]
                self.keygen_behaviour.clone(),
            ),
        }
    }

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
    ) -> TofndKeygenOutput {
        // try to create keygen with context
        let party_share_counts = ctx.share_counts()?;
        let keygen = match self.new_keygen(party_share_counts, &ctx).await {
            Ok(keygen) => keygen,
            Err(_) => {
                return Err(From::from("keygen instantiation failed"));
            }
        };

        // execute protocol and wait for completion
        let protocol_result = protocol::execute_protocol(
            keygen,
            chans,
            &ctx.uids,
            &ctx.share_counts,
            execute_span.clone(),
        )
        .await;

        match protocol_result {
            Ok(res) => {
                info!("Keygen completed");
                Ok(res)
            }
            Err(err) => Err(From::from(format!(
                "Keygen was not completed due to error: {}",
                err,
            ))),
        }
    }
}
