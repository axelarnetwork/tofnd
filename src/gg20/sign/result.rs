//! This module handles the aggregation and process of sign results.
//! When all sign threads finish, we aggregate their results and retrieve the signature of the message. The signature must be the same across all results.

use super::{proto, types::TofnSignOutput, Gg20Service};
use crate::TofndError;

use tokio::sync::oneshot;

// tonic cruft
use tokio::sync::mpsc;
use tonic::Status;

impl Gg20Service {
    /// handle results from all shares
    /// if all shares return a valid output, send the result to client
    /// if a share does not return a valid output, return a TofndError
    pub(super) async fn handle_results(
        aggregator_receivers: Vec<oneshot::Receiver<Result<TofnSignOutput, TofndError>>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        participant_uids: &[String],
    ) -> Result<(), TofndError> {
        // create vec to store all sign outputs
        // cannot use aggregator_receivers.map(|aggr| aggr.await??) because map() does not support async funcs
        let mut sign_outputs = Vec::with_capacity(aggregator_receivers.len());

        //  wait all sign threads and get signature
        for aggregator in aggregator_receivers {
            let sign_output = aggregator.await??;
            sign_outputs.push(sign_output);
        }

        // check if all signatures are the same
        if !is_all_same(&sign_outputs) {
            return Err(format!("Not all signatures are the same: {:#?}", sign_outputs).into());
        }

        // send signature to client
        stream_out_sender.send(Ok(proto::MessageOut::new_sign_result(
            participant_uids,
            sign_outputs[0].clone(),
        )))?;
        Ok(())
    }
}

fn is_all_same<T: PartialEq>(slice: &[T]) -> bool {
    slice.windows(2).all(|w| w[0] == w[1])
}
