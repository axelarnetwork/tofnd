use tofn::protocol::gg20::sign::SignOutput;

use super::{
    proto, protocol, routing::route_messages, Gg20Service, MessageDigest, PartyInfo,
    ProtocolCommunication,
};
use crate::TofndError;

use tokio::sync::oneshot;

// tonic cruft
use tokio::sync::mpsc;
use tonic::Status;

use tracing::{span, Level, Span};

mod execute;
mod init;
mod types;
use types::*;

impl Gg20Service {
    // we wrap the functionality of sign gRPC here because we can't handle errors
    // conveniently when spawning theads.
    pub async fn handle_sign(
        &mut self,
        mut stream_in: tonic::Streaming<proto::MessageIn>,
        mut stream_out_sender: mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        sign_span: Span,
    ) -> Result<(), TofndError> {
        // 1. Receive SignInit, open message, sanitize arguments
        // 2. Spawn N sign threads to execute the protocol in parallel; one of each of our shares
        // 3. Spawn 1 router thread to route messages from axelar core to the respective sign thread
        // 4. Wait for all sign threads to finish and aggregate all responses

        // get SignInit message from stream and sanitize arguments
        let mut stream_out = stream_out_sender.clone();
        let (sign_init, party_info) = self
            .handle_sign_init(&mut stream_in, &mut stream_out, sign_span.clone())
            .await?;

        // find my share count
        let my_share_count = party_info.shares.len();
        // create in and out channels for each share, and spawn as many threads
        let mut sign_senders = Vec::new();
        let mut aggregator_receivers = Vec::new();

        for my_tofnd_subindex in 0..my_share_count {
            let (sign_sender, sign_receiver) = mpsc::unbounded_channel();
            let (aggregator_sender, aggregator_receiver) = oneshot::channel();
            sign_senders.push(sign_sender);
            aggregator_receivers.push(aggregator_receiver);

            let chans = ProtocolCommunication::new(sign_receiver, stream_out_sender.clone());
            let ctx = Context::new(sign_init.clone(), party_info.clone(), my_tofnd_subindex)?;
            let gg20 = self.clone();

            // set up log state
            let log_info = ctx.log_info();
            let state = log_info.as_str();
            let execute_span = span!(parent: &sign_span, Level::INFO, "execute", state);

            // spawn sign threads
            tokio::spawn(async move {
                // get result of sign
                let signature = gg20.execute_sign(chans, &ctx, execute_span.clone()).await;
                let _ = aggregator_sender.send(signature);
            });
        }
        // spawn router thread
        let span = sign_span.clone();
        tokio::spawn(async move {
            route_messages(&mut stream_in, sign_senders, span).await;
        });

        let participant_share_counts = get_participant_share_counts(
            &party_info.tofnd.share_counts,
            &sign_init.participant_indices,
        );
        // wait for all sign threads to end, get their responses, and return signature
        handle_outputs(
            aggregator_receivers,
            &mut stream_out_sender,
            &sign_init.participant_uids,
            &participant_share_counts,
        )
        .await?;

        Ok(())
    }
}

fn get_participant_share_counts(all_shares: &[usize], signer_indices: &[usize]) -> Vec<usize> {
    signer_indices.iter().map(|i| all_shares[*i]).collect()
}

/// handle outputs from all participants
/// for each participant that returns a valid output, send the result to client
/// if a participant does not return a valid output, return a TofndError
async fn handle_outputs(
    aggregator_receivers: Vec<oneshot::Receiver<Result<SignOutput, TofndError>>>,
    stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
    participant_uids: &[String],
    participant_share_counts: &[usize],
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
        participant_share_counts,
        sign_output,
    )))?;
    Ok(())
}
