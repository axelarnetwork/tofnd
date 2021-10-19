//! This module handles the aggregation and process of sign results.
//! When all sign threads finish, we aggregate their results and retrieve the signature of the message. The signature must be the same across all results.

use super::{proto, types::TofnSignOutput, Gg20Service};

// tonic cruft
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tonic::Status;

// error handling
use crate::TofndResult;
use anyhow::anyhow;

impl Gg20Service {
    /// handle results from all shares
    /// if all shares return a valid output, send the result to client
    /// if a share does not return a valid output, return an [anyhow!]
    pub(super) async fn handle_results(
        aggregator_receivers: Vec<oneshot::Receiver<TofndResult<TofnSignOutput>>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        participant_uids: &[String],
    ) -> TofndResult<()> {
        // create vec to store all sign outputs
        // cannot use aggregator_receivers.map(|aggr| aggr.await??) because map() does not support async funcs
        let mut sign_outputs = Vec::with_capacity(aggregator_receivers.len());

        //  wait all sign threads and get signature
        for aggregator in aggregator_receivers {
            let sign_output = aggregator.await??;
            sign_outputs.push(sign_output);
        }

        // sanity check: check if all shares produced the same signature
        let first_sign_output = &sign_outputs[0];
        // skip() first element of sign outputs to avoid extra loop
        for (i, sign_output) in sign_outputs.iter().enumerate().skip(1) {
            if sign_output != first_sign_output {
                let mut error_msg = format!(
                    "Signature mismatch between shares [{}] and [{}]. More mismatches may exist.",
                    0, i
                );
                error_msg = format!(
                    "{}\nReceived signatures: {:#?}",
                    error_msg,
                    sign_output.iter().enumerate().collect::<Vec<_>>()
                );
                return Err(anyhow!(error_msg));
            }
        }

        // send signature to client
        stream_out_sender.send(Ok(proto::MessageOut::new_sign_result(
            participant_uids,
            sign_outputs[0].clone(),
        )))?;
        Ok(())
    }
}
