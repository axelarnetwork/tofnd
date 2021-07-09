use tracing::{span, Level, Span};

use tofn::protocol::gg20::keygen::{crimes::Crime, KeygenOutput};

use super::{
    proto::{self, message_out::keygen_result},
    protocol::{self, map_tofnd_to_tofn_idx},
    routing::route_messages,
    Gg20Service, PartyInfo, ProtocolCommunication,
};
use crate::{kv_manager::KeyReservation, TofndError};

use tonic::Status;

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};

pub mod types;
use types::*;

mod aggregate;
mod execute;
mod init;

// wrapper type for proto::message_out::new_keygen_result
pub(super) type KeygenResultData = Result<keygen_result::KeygenOutput, Vec<Vec<Crime>>>;

impl Gg20Service {
    // we wrap the functionality of keygen gRPC here because we can't handle errors
    // conveniently when spawning theads.
    pub async fn handle_keygen(
        &mut self,
        mut stream_in: tonic::Streaming<proto::MessageIn>,
        mut stream_out_sender: mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        keygen_span: Span,
    ) -> Result<(), TofndError> {
        // 1. Receive KeygenInit, open message, sanitize arguments
        // 2. Spawn N keygen threads to execute the protocol in parallel; one of each of our shares
        // 3. Spawn 1 router thread to route messages from client to the respective keygen thread
        // 4. Wait for all keygen threads to finish and aggregate all responses

        // get KeygenInit message from stream, sanitize arguments and reserve key
        let (keygen_init, key_uid_reservation) = self
            .handle_keygen_init(&mut stream_in, keygen_span.clone())
            .await?;

        // find my share count to allocate channel vectors
        let my_share_count = keygen_init.my_shares_count();

        // create in and out channels for each share, and spawn as many threads
        let mut keygen_senders = Vec::with_capacity(my_share_count);
        let mut aggregator_receivers = Vec::with_capacity(my_share_count);

        for my_tofnd_subindex in 0..my_share_count {
            let (keygen_sender, keygen_receiver) = mpsc::unbounded_channel();
            let (aggregator_sender, aggregator_receiver) = oneshot::channel();
            keygen_senders.push(keygen_sender);
            aggregator_receivers.push(aggregator_receiver);

            let chans = ProtocolCommunication::new(keygen_receiver, stream_out_sender.clone());
            let ctx = Context::new(&keygen_init, keygen_init.my_index, my_tofnd_subindex);
            let gg20 = self.clone(); // need to clone service because tokio thread takes ownership

            // set up log state
            let log_info = ctx.log_info();
            let state = log_info.as_str();
            let execute_span = span!(parent: &keygen_span, Level::DEBUG, "execute", state);

            // spawn keygen threads
            tokio::spawn(async move {
                // get result of keygen
                let secret_key_share = gg20.execute_keygen(chans, &ctx, execute_span.clone()).await;
                let _ = aggregator_sender.send(secret_key_share);
            });
        }

        let span = keygen_span.clone();
        tokio::spawn(async move {
            route_messages(&mut stream_in, keygen_senders, span).await;
        });

        // wait for all keygen threads to end, aggregate their responses, and store data in KV store
        self.aggregate_messages(
            aggregator_receivers,
            &mut stream_out_sender,
            key_uid_reservation,
            keygen_init,
        )
        .await?;

        Ok(())
    }
}
