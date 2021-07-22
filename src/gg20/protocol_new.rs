//! Abstract functionality used by keygen, sign, etc.
use tofn::{
    refactor::collections::TypedUsize,
    refactor::sdk::api::{Protocol, ProtocolOutput, Round},
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::TofndError;

use tracing::{debug, error, span, warn, Level, Span};

use super::{proto, ProtocolCommunication};

type TofndResult<T> = Result<T, TofndError>;

/// execute gg20 protocol
pub(super) async fn execute_protocol<F, K, P>(
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
    let total_round_p2p_msgs = total_num_of_shares * (total_num_of_shares - 1); // total number of messages is n(n-1)

    let mut round_count = 0;
    while let Protocol::NotDone(mut round) = party {
        round_count += 1;

        // handle outgoing traffic
        handle_outgoing(
            &chans.sender,
            &round,
            &party_uids,
            round_count,
            span.clone(),
        )?;

        // collect incoming traffic
        handle_incoming(
            &mut chans.receiver,
            &mut round,
            &party_uids,
            total_round_p2p_msgs,
            total_num_of_shares,
            round_count,
            span.clone(),
        )
        .await?;

        // check if everything was ok this round
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

fn handle_outgoing<F, K, P>(
    sender: &UnboundedSender<Result<proto::MessageOut, tonic::Status>>,
    round: &Round<F, K, P>,
    party_uids: &[String],
    round_count: usize,
    span: Span,
) -> TofndResult<()> {
    let send_span = span!(parent: &span, Level::DEBUG, "outgoing", round = round_count);
    let _start = send_span.enter();
    debug!("begin");
    // send outgoing bcasts
    if let Some(bcast) = round.bcast_out() {
        debug!("generating out bcast");
        sender.send(Ok(proto::MessageOut::new_bcast(bcast)))?
    }
    // send outgoing p2ps
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
            // TODO: 'reveiver_id' is not needed from the client anymore and should be removed from the protofile
            sender.send(Ok(proto::MessageOut::new_p2p("receiver_id", p2p)))?
        }
    }
    debug!("finished");
    Ok(())
}

async fn handle_incoming<F, K, P>(
    receiver: &mut UnboundedReceiver<Option<proto::TrafficIn>>,
    round: &mut Round<F, K, P>,
    party_uids: &[String],
    total_round_p2p_msgs: usize,
    total_num_of_shares: usize,
    round_count: usize,
    span: Span,
) -> TofndResult<()> {
    let mut p2p_msg_count = 0;
    let mut bcast_msg_count = 0;

    // loop until no more messages are needed for this round
    while round.expecting_more_msgs_this_round() {
        // get message from router
        let traffic = receiver.recv().await.ok_or(format!(
            "{}: stream closed by client before protocol has completed",
            round_count
        ));

        // we have to unpeal traffic
        let traffic = match traffic {
            Ok(traffic_opt) => match traffic_opt {
                Some(traffic) => traffic,
                None => {
                    warn!("ignore incoming msg: missing `data` field");
                    continue;
                }
            },
            Err(_) => {
                error!("internal channel closed prematurely");
                break;
            }
        };

        // We have to spawn a new span it in each loop because `async` calls don't work well with tracing
        // See details on how we need to make spans curve around `.await`s here:
        // https://docs.rs/tracing/0.1.25/tracing/span/index.html#entering-a-span
        let recv_span = span!(parent: &span, Level::DEBUG, "incoming", round = round_count);
        let _start = recv_span.enter();

        // log incoming message
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

        // get sender's party index
        let from = party_uids
            .iter()
            .position(|uid| uid == &traffic.from_party_uid)
            .ok_or("from uid does not exist in party uids")?;

        // try to set a message
        if round
            .msg_in(TypedUsize::from_usize(from), &traffic.payload)
            .is_err()
        {
            return Err(From::from(format!(
                "error calling tofn::msg_in with [from: {}]",
                from
            )));
        };
    }

    Ok(())
}
