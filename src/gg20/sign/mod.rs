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

// logging
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
        // 1. Receive SignInit, open message, sanitize arguments -> init mod
        // 2. Spawn N sign threads to execute the protocol in parallel; one of each of our shares -> execute mod
        // 3. Spawn 1 router thread to route messages from client to the respective sign thread -> routing mod
        // 4. Wait for all sign threads to finish and aggregate all responses

        // 1.
        // get SignInit message from stream and sanitize arguments
        let mut stream_out = stream_out_sender.clone();
        let (sign_init, party_info) = self
            .handle_sign_init(&mut stream_in, &mut stream_out, sign_span.clone())
            .await?;

        // 2.
        // find my share count to allocate channel vectors
        let my_share_count = party_info.shares.len();
        // create in and out channels for each share, and spawn as many threads
        let mut sign_senders = Vec::with_capacity(my_share_count);
        let mut aggregator_receivers = Vec::with_capacity(my_share_count);

        for my_tofnd_subindex in 0..my_share_count {
            // channels for communication between router (sender) and protocol threads (receivers)
            let (sign_sender, sign_receiver) = mpsc::unbounded_channel();
            sign_senders.push(sign_sender);
            // channels for communication between protocol threads (senders) and final result aggregator (receiver)
            let (aggregator_sender, aggregator_receiver) = oneshot::channel();
            aggregator_receivers.push(aggregator_receiver);

            // wrap channels needed by internal threads; receiver chan for router and sender chan gRPC stream
            let chans = ProtocolCommunication::new(sign_receiver, stream_out_sender.clone());
            // wrap all context data needed for each thread
            let ctx = Context::new(sign_init.clone(), party_info.clone(), my_tofnd_subindex)?;
            // clone gg20 service because tokio thread takes ownership
            let gg20 = self.clone();

            // set up log state
            let log_info = ctx.log_info();
            let state = log_info.as_str();
            let execute_span = span!(parent: &sign_span, Level::INFO, "execute", state);

            // spawn sign threads
            tokio::spawn(async move {
                // get result of sign
                let signature = gg20.execute_sign(chans, &ctx, execute_span.clone()).await;
                // send result to aggregator
                let _ = aggregator_sender.send(signature);
            });
        }

        // 3.
        // spin up router thread and return immediately
        let span = sign_span.clone();
        tokio::spawn(async move {
            route_messages(&mut stream_in, sign_senders, span).await;
        });

        // 4.
        // find total sign share number
        let sign_share_counts = Self::sign_share_count(
            &party_info.tofnd.share_counts,
            &sign_init.participant_indices,
        )?;

        // wait for all sign threads to end, get responses, and return signature
        Self::handle_outputs(
            aggregator_receivers,
            &mut stream_out_sender,
            &sign_init.participant_uids,
            &sign_share_counts,
        )
        .await?;

        Ok(())
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

    fn sign_share_count(
        all_shares: &[usize],
        sign_indices: &[usize],
    ) -> Result<Vec<usize>, TofndError> {
        let mut sign_shares = Vec::with_capacity(sign_indices.len());
        for sign_index in sign_indices {
            let sign_share = *all_shares
                .get(*sign_index)
                .ok_or("Sign index out of bounds")?;
            sign_shares.push(sign_share);
        }
        Ok(sign_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_shares_number() {
        // all parties participate in sign
        let all_shares = vec![1, 2, 3, 4, 5];
        let sign_indices = vec![0, 1, 2, 3, 4];
        assert_eq!(
            Gg20Service::sign_share_count(&all_shares, &sign_indices).unwrap(),
            all_shares
        );

        let sign_indices = vec![3];
        assert_eq!(
            Gg20Service::sign_share_count(&all_shares, &sign_indices).unwrap(),
            vec![4] // party 3 has 4 shares
        );

        let sign_indices = vec![3, 1];
        assert_eq!(
            Gg20Service::sign_share_count(&all_shares, &sign_indices).unwrap(),
            vec![4, 2] // party 3 has 4 shares, party 1 has 2 shares
        );

        let sign_indices = vec![5]; // index out of bounds
        assert!(Gg20Service::sign_share_count(&all_shares, &sign_indices).is_err(),);
    }
}
