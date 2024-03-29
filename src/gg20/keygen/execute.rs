//! This module creates and executes the keygen protocol
//! On success it returns [super::TofnKeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [anyhow!] error if [Keygen] struct cannot be instantiated.

use super::{
    proto,
    types::{Context, PartyShareCounts, TofndKeygenOutput},
    Gg20Service, ProtocolCommunication,
};

use crate::gg20::protocol;
use tofn::{
    gg20::keygen::{new_keygen, KeygenProtocol},
    sdk::api::TofnResult,
};

// logging
use tracing::{info, Span};

// error handling
use anyhow::anyhow;

impl Gg20Service {
    /// create a new keygen.
    /// The field of Gg20Service `safe_keygen` dictates whether the new keygen will use big primes of not
    /// TODO: support `cfg(feature="unsafe")` in the future instead of matching `gg20.safe_keygen`
    async fn new_keygen(
        &self,
        party_share_counts: PartyShareCounts,
        ctx: &Context,
    ) -> TofnResult<KeygenProtocol> {
        new_keygen(
            party_share_counts,
            ctx.threshold,
            ctx.tofnd_index,
            ctx.tofnd_subindex,
            &ctx.party_keygen_data,
            #[cfg(feature = "malicious")]
            self.cfg.behaviours.keygen.clone(),
        )
    }

    /// create and execute keygen protocol and returning the result.
    /// if the protocol cannot be instantiated, return a [anyhow!]
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
        let keygen = self
            .new_keygen(party_share_counts, ctx)
            .await
            .map_err(|_| anyhow!("keygen protocol instantiation failed"))?;

        // execute protocol and wait for completion
        let protocol_result = protocol::execute_protocol(
            keygen,
            chans,
            &ctx.uids,
            &ctx.share_counts,
            execute_span.clone(),
        )
        .await;

        let res = protocol_result
            .map_err(|err| anyhow!("Keygen was not completed due to error: {}", err))?;

        info!("Keygen completed");
        Ok(res)
    }
}
