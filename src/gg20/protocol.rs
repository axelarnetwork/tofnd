//! Abstract functionality used by keygen, sign, etc.
use tofn::protocol::Protocol;

use super::{proto, ProtocolCommunication};
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;

use tracing::{info, span, warn, Level, Span};

pub fn map_tofnd_to_tofn_idx(
    tofnd_index: usize,
    tofnd_subindex: usize,
    party_share_counts: &[usize],
) -> usize {
    let s: usize = party_share_counts[..tofnd_index].iter().sum();
    s + tofnd_subindex
}

fn map_tofn_to_tofnd_idx(
    tofn_index: usize,
    party_share_counts: &[usize],
) -> Result<(usize, usize), TofndError> {
    let mut sum = 0;
    for (tofnd_index, count) in party_share_counts.iter().enumerate() {
        sum += count;
        if tofn_index < sum {
            return Ok((tofnd_index, tofn_index - (sum - count)));
        }
    }
    Err(From::from(format!(
        "Tofn index {} does not correspond to a tofnd index",
        tofn_index
    )))
}

pub(super) async fn execute_protocol(
    protocol: &mut impl Protocol,
    mut chan: ProtocolCommunication<
        Option<proto::TrafficIn>,
        Result<proto::MessageOut, tonic::Status>,
    >,
    party_uids: &[String],
    party_share_counts: &[usize],
    party_indices: &[usize],
    span: Span,
) -> Result<(), TofndError> {
    let mut round = 0;

    // TODO runs an extra iteration!
    while !protocol.done() {
        let pspan = span!(parent: &span, Level::INFO, "", round);
        let _start = pspan.enter();
        round += 1;
        let log_prefix_round = format!("{}", round);
        info!("begin");
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            info!("out bcast");
            chan.sender
                .send(Ok(proto::MessageOut::new_bcast(bcast)))
                .await?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    let (tofnd_idx, _) =
                        map_tofn_to_tofnd_idx(party_indices[i], party_share_counts)?;
                    info!("out p2p to [{}]", party_uids[tofnd_idx]);
                    chan.sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[tofnd_idx], &p2p)))
                        .await?;
                }
            }
        }

        // collect incoming messages
        // println!("{}: wait for incoming messages...", log_prefix_round);
        info!("wait for incoming messages");
        while protocol.expecting_more_msgs_this_round() {
            let traffic = chan.receiver.next().await.ok_or(format!(
                "{}: stream closed by client before protocol has completed",
                log_prefix_round
            ))?;
            if traffic.is_none() {
                warn!("ignore incoming msg: missing `data` field");
                continue;
            }
            let traffic = traffic.unwrap();
            protocol.set_msg_in(&traffic.payload)?;
        }
        info!("got all incoming messages");
        info!("end");
    }
    info!("end");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tofn_to_tofnd() {
        struct Test {
            v: Vec<usize>,
            test_cases: Vec<(usize, Option<(usize, usize)>)>,
        }

        let tests = vec![
            Test {
                v: vec![1, 2, 3],
                test_cases: vec![
                    (0, Some((0, 0))),
                    (1, Some((1, 0))),
                    (2, Some((1, 1))),
                    (3, Some((2, 0))),
                    (4, Some((2, 1))),
                    (5, Some((2, 2))),
                    (6, None),
                ],
            },
            Test {
                v: vec![3, 2, 1],
                test_cases: vec![
                    (0, Some((0, 0))),
                    (1, Some((0, 1))),
                    (2, Some((0, 2))),
                    (3, Some((1, 0))),
                    (4, Some((1, 1))),
                    (5, Some((2, 0))),
                    (6, None),
                ],
            },
            Test {
                v: vec![1, 1, 1, 1, 1, 1],
                test_cases: vec![
                    (0, Some((0, 0))),
                    (1, Some((1, 0))),
                    (2, Some((2, 0))),
                    (3, Some((3, 0))),
                    (4, Some((4, 0))),
                    (5, Some((5, 0))),
                    (6, None),
                ],
            },
        ];

        for t in tests {
            for case in t.test_cases {
                let (tofn, tofnd) = case;
                assert_eq!(map_tofn_to_tofnd_idx(tofn, &t.v).ok(), tofnd);
                if let Some(tofnd) = tofnd {
                    assert_eq!(map_tofnd_to_tofn_idx(tofnd.0, tofnd.1, &t.v), tofn);
                }
            }
        }
    }

    #[test]
    fn tofnd_to_tofn() {
        let v = vec![1, 2, 3];
        let test_cases = vec![
            ((0, 0), 0),
            ((1, 0), 1),
            ((1, 1), 2),
            ((2, 0), 3),
            ((2, 1), 4),
            ((2, 2), 5),
        ];
        for t in test_cases {
            assert_eq!(map_tofnd_to_tofn_idx(t.0 .0, t.0 .1, &v), t.1);
            assert_eq!(map_tofn_to_tofnd_idx(t.1, &v).ok(), Some((t.0 .0, t.0 .1)));
        }
    }
}
