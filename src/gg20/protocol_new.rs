use tofn::{
    refactor::collections::TypedUsize,
    refactor::sdk::api::{Protocol, ProtocolOutput},
};

use crate::TofndError;

use super::protocol::map_tofn_to_tofnd_idx;

use tracing::{debug, span, warn, Level, Span};

use super::{proto, ProtocolCommunication};

type TofndResult<T> = Result<T, TofndError>;

pub async fn execute_protocol<F, K, P>(
    mut party: Protocol<F, K, P>,
    mut chans: ProtocolCommunication<
        Option<proto::TrafficIn>,
        Result<proto::MessageOut, tonic::Status>,
    >,
    party_uids: &[String],
    party_share_counts: &[usize],
    span: Span,
) -> TofndResult<ProtocolOutput<F, P>>
where
    K: Clone,
{
    // set up counters for logging
    let total_num_of_shares = party_share_counts.iter().fold(0, |acc, s| acc + *s);
    let total_round_p2p_msgs = total_num_of_shares * (total_num_of_shares - 1);

    let mut r = 0;
    while let Protocol::NotDone(mut round) = party {
        r += 1;

        let send_span = span!(parent: &span, Level::DEBUG, "protocol outgoing", round = r);
        let start = send_span.enter();
        debug!("begin");
        // send outgoing messages
        if let Some(bcast) = round.bcast_out() {
            debug!("generating out bcast");
            chans.sender.send(Ok(proto::MessageOut::new_bcast(bcast)))?
        }
        if let Some(p2ps_out) = round.p2ps_out() {
            let mut p2p_msg_count = 1;
            for (i, p2p) in p2ps_out.iter() {
                let (tofnd_idx, _) = map_tofn_to_tofnd_idx(i.as_usize(), party_share_counts)?;
                debug!(
                    "out p2p to [{}] ({}/{})",
                    party_uids[tofnd_idx],
                    p2p_msg_count,
                    p2ps_out.len() - 1
                );
                p2p_msg_count += 1;
                chans
                    .sender
                    .send(Ok(proto::MessageOut::new_p2p(&party_uids[tofnd_idx], p2p)))?
            }
        }

        debug!("send all outgoing messages; waiting for incoming messages",);
        drop(start);

        // collect incoming messages
        let mut p2p_msg_count = 0;
        let mut bcast_msg_count = 0;
        while round.expecting_more_msgs_this_round() {
            let traffic = chans.receiver.recv().await.ok_or(format!(
                "{}: stream closed by client before protocol has completed",
                r
            ))?;
            if traffic.is_none() {
                warn!("ignore incoming msg: missing `data` field");
                continue;
            }
            let traffic = traffic.unwrap();

            let recv_span = span!(parent: &span, Level::DEBUG, "protocol incoming", round = r);
            let start = recv_span.enter();
            if traffic.is_broadcast {
                bcast_msg_count += 1;
                debug!(
                    "got incoming bcast message {}/{}",
                    bcast_msg_count, total_num_of_shares
                );
            } else {
                p2p_msg_count += 1;
                debug!(
                    "got incoming p2p message {}/{}",
                    p2p_msg_count, total_round_p2p_msgs
                );
            }
            drop(start);

            let from = party_uids
                .iter()
                .position(|uid| uid == &traffic.from_party_uid)
                .ok_or("from uid does not exist in party uids")?;

            if let Err(_) = round.msg_in(TypedUsize::from_usize(from), &traffic.payload) {
                return Err(From::from("error calling tofn::msg_in"));
            };
        }

        let exec_span = span!(parent: &span, Level::DEBUG, "protocol execution", r);
        let _start = exec_span.enter();
        debug!("got all {} incoming bcast messages", bcast_msg_count);
        debug!("got all {} incoming p2p messages", p2p_msg_count);
        debug!("completed");

        party = match round.execute_next_round() {
            Ok(party) => party,
            Err(_) => {
                return Err(From::from("Error in tofn::execute_next_round"));
            }
        };
    }
    match party {
        Protocol::NotDone(_) => Err(From::from("Protocol failed to complete")),
        Protocol::Done(result) => Ok(result),
    }
}
