//! This module handles the aggregation of process of keygen results.
//! When all keygen threads finish, we aggregate their results and retrieve:
//!  1. the public key - must be the same across all results; stored in KvStore
//!  2. all secret share data - data used to allow parties to participate to future Signs; stored in KvStore
//!  3. all secret share recovery info - information used to allow client to issue secret share recovery in case of data loss; sent to client

use crate::{
    grpc::{
        keygen::types::common::{KeygenInitSanitized, KeygenOutput, KeygenType, TofndKeygenOutput},
        service::Service,
    },
    kv_manager::types::KeyReservation,
    proto,
};

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};
use tonic::Status;

// error handling
use crate::TofndResult;
use anyhow::anyhow;

impl Service {
    /// aggregate results from all keygen threads, create a record and insert it in the KvStore
    pub(in super::super) async fn aggregate_results(
        &self,
        aggregator_receivers: Vec<oneshot::Receiver<TofndKeygenOutput>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
        keygen_type: KeygenType,
    ) -> TofndResult<()> {
        // wait all keygen threads and aggregate results
        // can't use `map_err` because of `.await` func :(
        let keygen_outputs = match Self::aggregate_keygen_outputs(aggregator_receivers).await {
            Ok(keygen_outputs) => keygen_outputs,
            Err(err) => {
                self.kv.unreserve_key(key_uid_reservation).await;
                return Err(anyhow!(
                    "Error at Keygen output aggregation. Unreserving key {}",
                    err
                ));
            }
        };

        // TODO: refactor this into abstract code instead of matching keygen type
        match keygen_type {
            KeygenType::Gg20 => {
                self.aggregate_gg20_results(
                    keygen_outputs,
                    stream_out_sender,
                    key_uid_reservation,
                    keygen_init,
                )
                .await
            }
            KeygenType::Multisig => {
                self.aggregate_multisig_results(
                    keygen_outputs,
                    stream_out_sender,
                    key_uid_reservation,
                    keygen_init,
                )
                .await
            }
        }
    }

    /// wait all keygen threads and get keygen outputs
    async fn aggregate_keygen_outputs(
        aggregator_receivers: Vec<Receiver<TofndKeygenOutput>>,
    ) -> TofndResult<Vec<KeygenOutput>> {
        let mut keygen_outputs = Vec::with_capacity(aggregator_receivers.len());

        for aggregator in aggregator_receivers {
            let res = aggregator.await??;
            keygen_outputs.push(res);
        }

        Ok(keygen_outputs)
    }
}
