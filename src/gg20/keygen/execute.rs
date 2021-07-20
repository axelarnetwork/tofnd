//! This module creates and executes the keygen protocol
//! On success it returns [KeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [TofndError] if [Keygen] struct cannot be instantiated.

use super::{
    proto,
    types::{Context, TofndKeygenOutput},
    Gg20Service, ProtocolCommunication,
};

use tofn::refactor::collections::TypedUsize;
use tofn::refactor::keygen::new_keygen;
use tofn::refactor::sdk::api::PartyShareCounts;

use crate::gg20::protocol_new;

// logging
use tracing::{info, Span};

impl Gg20Service {
    /// create and execute keygen protocol and returning the result.
    /// if the protocol cannot be instantiated, return a TofndError
    pub(super) async fn execute_keygen_new(
        &self,
        chans: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        ctx: &Context,
        execute_span: Span,
    ) -> TofndKeygenOutput {
        // create keygen with context
        let party_share_counts = match PartyShareCounts::from_vec(ctx.share_counts.clone()) {
            Ok(party_share_counts) => party_share_counts,
            Err(_) => {
                return Err(From::from("failed to create party_share_counts"));
            }
        };
        let keygen = match new_keygen(
            party_share_counts,
            ctx.threshold,
            TypedUsize::from_usize(ctx.tofn_index()),
            &self.seed().await.unwrap(),
            &ctx.nonce(),
            #[cfg(feature = "malicious")]
            self.keygen_behaviour.clone(),
        ) {
            Ok(keygen) => keygen,
            Err(_) => {
                return Err(From::from("keygen instantiation failed"));
            }
        };

        // execute protocol and wait for completion
        let protocol_result = protocol_new::execute_protocol(
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
            Err(_) => Err(From::from("Keygen was not completed due to faults")),
        }
    }
}
