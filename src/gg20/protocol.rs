//! Abstract functionality used by keygen, sign, etc.
use tofn::protocol::Protocol;

use super::proto;
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;

use serde::{Deserialize, Serialize};

// final output of keygen
#[derive(Serialize, Deserialize)]
pub struct TofndP2pMsg {
    // TODO: &`a[u8]
    pub payload: Vec<u8>,
    pub subindex: usize,
}

fn map_tofnd_to_tofn_idx(tofnd_index: usize, party_share_counts: &[u32]) -> u32 {
    party_share_counts[..=tofnd_index].iter().sum()
}

fn map_tofn_to_tofnd_idx(tofn_index: usize, party_share_counts: &[u32]) -> Option<(usize, usize)> {
    let mut sum: u32 = 0;
    for (tofnd_index, count) in party_share_counts.into_iter().enumerate() {
        sum += count;
        if tofn_index < sum as usize {
            return Some((tofnd_index, tofn_index - (sum - count) as usize));
        }
    }
    None
}

// TODO: use the same execute_keygen for sign. We keep this not to break sign.
pub(super) async fn execute_protocol_sign(
    protocol: &mut impl Protocol,
    in_stream: &mut tonic::Streaming<proto::MessageIn>,
    out_sender: &mut mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
    log_prefix: &str,
) -> Result<(), TofndError> {
    println!("{} protocol: begin", log_prefix);
    let mut round = 0;

    // TODO runs an extra iteration!
    while !protocol.done() {
        round += 1;
        let log_prefix_round = format!("{} round {}", log_prefix, round);
        println!("{}: begin", log_prefix_round);
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            println!("{}: out bcast", log_prefix_round);
            out_sender
                .send(Ok(proto::MessageOut::new_bcast(bcast)))
                .await?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    println!("{}: out p2p to [{}]", log_prefix_round, party_uids[i]);
                    out_sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[i], p2p)))
                        .await?;
                }
            }
        }

        // collect incoming messages
        // println!("{}: wait for incoming messages...", log_prefix_round);
        while protocol.expecting_more_msgs_this_round() {
            let msg_data = in_stream
                .next()
                .await
                .ok_or(format!(
                    "{}: stream closed by client before protocol has completed",
                    log_prefix_round
                ))??
                .data;
            // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
            if msg_data.is_none() {
                println!(
                    "{}: WARNING: ignore incoming msg: missing `data` field",
                    log_prefix_round
                );
                continue;
            }
            let traffic = match msg_data.unwrap() {
                proto::message_in::Data::Traffic(t) => t,
                _ => {
                    println!(
                        "{}: WARNING: ignore incoming msg: expect `data` to be TrafficIn type",
                        log_prefix_round
                    );
                    continue;
                }
            };
            println!("{}: incoming msg received", log_prefix_round);
            protocol.set_msg_in(&traffic.payload)?;
        }
        println!("{}: end", log_prefix_round);
    }
    println!("{} protocol: end", log_prefix);
    Ok(())
}

pub(super) async fn execute_protocol(
    protocol: &mut impl Protocol,
    mut in_channel: mpsc::Receiver<Option<proto::TrafficIn>>,
    out_sender: &mut mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
    party_share_counts: &[u32],
    log_prefix: &str,
) -> Result<(), TofndError> {
    println!("{} protocol: begin", log_prefix);
    let mut round = 0;

    // TODO runs an extra iteration!
    while !protocol.done() {
        round += 1;
        let log_prefix_round = format!("{} round {}", log_prefix, round);
        println!("{}: begin", log_prefix_round);
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            println!("{}: out bcast", log_prefix_round);
            out_sender
                .send(Ok(proto::MessageOut::new_bcast(bcast)))
                .await?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    println!("{}: out p2p to [{}]", log_prefix_round, party_uids[i]);
                    out_sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[i], p2p)))
                        .await?;
                }
            }
        }

        // collect incoming messages
        // println!("{}: wait for incoming messages...", log_prefix_round);
        while protocol.expecting_more_msgs_this_round() {
            let traffic = in_channel
                .next()
                .await
                .ok_or(format!(
                    "{}: stream closed by client before protocol has completed",
                    log_prefix_round
                ))?
                // Question: should we return an error here of just print a warning and continue?
                .ok_or(format!(
                    "{}: protocol was expecting a message, but None was reveived",
                    log_prefix_round
                ))?;
            println!("{}: incoming msg received", log_prefix_round);
            protocol.set_msg_in(&traffic.payload)?;
        }
        println!("{}: end", log_prefix_round);
    }
    println!("{} protocol: end", log_prefix);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tofn_to_tofnd() {
        let v = vec![1, 2, 3];
        let test_cases = vec![
            (0, Some((0, 0))),
            (1, Some((1, 0))),
            (2, Some((1, 1))),
            (3, Some((2, 0))),
            (4, Some((2, 1))),
            (5, Some((2, 2))),
            (6, None),
        ];
        let v2 = vec![3, 2, 1];
        let test_cases_2 = vec![
            (0, Some((0, 0))),
            (1, Some((0, 1))),
            (2, Some((0, 2))),
            (3, Some((1, 0))),
            (4, Some((1, 1))),
            (5, Some((2, 0))),
            (6, None),
        ];
        for t in test_cases {
            assert_eq!(map_tofn_to_tofnd_idx(t.0, &v), t.1);
        }
        for t in test_cases_2 {
            assert_eq!(map_tofn_to_tofnd_idx(t.0, &v2), t.1);
        }
    }

    #[test]
    fn tofnd_to_tofn() {
        let v = vec![1, 2, 3, 4, 5, 6];
        let test_cases = vec![(0, 1), (1, 3), (2, 6), (3, 10), (4, 15), (5, 21)];
        for t in test_cases {
            assert_eq!(map_tofnd_to_tofn_idx(t.0, &v), t.1);
        }
    }
}
