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
        //  wait all sign threads and get signature
        let mut sign_output = None;
        for aggregator in aggregator_receivers {
            sign_output = Some(aggregator.await??);
        }
        let sign_output = sign_output.ok_or("no output returned from waitgroup")?;

        // send signature to client
        stream_out_sender.send(Ok(proto::MessageOut::new_sign_result(
            participant_uids,
            sign_output,
        )))?;
        Ok(())
    }
}
