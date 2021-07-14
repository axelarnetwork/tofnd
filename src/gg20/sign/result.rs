use tofn::protocol::gg20::sign::SignOutput;

use super::{proto, Gg20Service};
use crate::TofndError;

use tokio::sync::oneshot;

// tonic cruft
use tokio::sync::mpsc;
use tonic::Status;

impl Gg20Service {
    /// handle outputs from all participants
    /// for each participant that returns a valid output, send the result to client
    /// if a participant does not return a valid output, return a TofndError
    pub(super) async fn handle_outputs(
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

    /// get share counts of sign participants
    pub(super) fn sign_share_count(
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

        // party 3 has 4 shares
        let sign_indices = vec![3];
        assert_eq!(
            Gg20Service::sign_share_count(&all_shares, &sign_indices).unwrap(),
            vec![4]
        );

        // party 3 has 4 shares, party 1 has 2 shares
        let sign_indices = vec![3, 1];
        assert_eq!(
            Gg20Service::sign_share_count(&all_shares, &sign_indices).unwrap(),
            vec![4, 2]
        );

        // index out of bounds
        let sign_indices = vec![5];
        assert!(Gg20Service::sign_share_count(&all_shares, &sign_indices).is_err());
    }
}
