//! Abstract functionality used by keygen, sign, etc.
use tofn::protocol::{IndexRange, Protocol};

use super::{proto, ProtocolCommunication};
use crate::TofndError;

use tracing::{debug, span, warn, Level, Span};

// TODO: add unit test
pub fn map_tofnd_to_tofn_idx(
    tofnd_index: usize,
    tofnd_subindex: usize,
    party_share_counts: &[usize],
) -> usize {
    let s: usize = party_share_counts[..tofnd_index].iter().sum();
    s + tofnd_subindex
}

// TODO: add unit test
pub(super) fn map_tofn_to_tofnd_idx(
    tofn_index: usize,
    party_share_counts: &[usize],
) -> Result<(usize, usize), TofndError> // (party_index, share_index)
{
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

pub(super) async fn _execute_protocol(
    protocol: &mut impl Protocol,
    mut chan: ProtocolCommunication<
        Option<proto::TrafficIn>,
        Result<proto::MessageOut, tonic::Status>,
    >,
    party_uids: &[String],
    party_share_counts: &[usize],
    span: Span,
) -> Result<(), TofndError> {
    let mut round = 0;

    // each share broadcasts their p2ps and we don't send our p2ps to ourselves, so we expect n(n-1) p2ps in total
    let total_num_of_shares = party_share_counts.iter().fold(0, |acc, s| acc + *s);
    let total_round_p2p_msgs = total_num_of_shares * (total_num_of_shares - 1);

    // protocol_info macro is used to create a temporary span.
    // We need temp spans because logs are getting scrambled when async code is
    // executed inside a span, so we create a temp span and discard it immediately after logging.
    // We define this macro here to implicitly capture the value of local 'round'.
    // See details on how we need to make spans curve around `.await`s here:
    // https://docs.rs/tracing/0.1.25/tracing/span/index.html#entering-a-span
    // protocol_info carries all the information from keygen/sign spans as prefix e.g.:
    // keygen/sign [key] party [A] with (t,n)=(7,5)"}:{round=1}: <message>
    // call as:
    //   protocol_info("message") or
    //   protocol_info("my message and some numbers {}, {}, {}", i, j, k)
    macro_rules! protocol_info {
        // read exactly one argument $e and as many $opt args as the user provides
        // we use opt* arguments to match calls with place holders much like
        // println("{}, {}", i, j) does.
        ($e:expr $(, $opt:expr)* ) => {
            // create a protocol span
            let protocol_span = span!(parent: &span, Level::DEBUG, "protocol", round);
            // enter span
            let _start = protocol_span.enter();
            // log message
            debug!($e $(, $opt)*);
            // spans are RAII objects. Our span exits here.
            // https://docs.rs/tracing/0.1.25/tracing/#spans-1
        };
    }

    // TODO runs an extra iteration!
    while !protocol.done() {
        round += 1;
        protocol_info!("begin");
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            protocol_info!("generating out bcast");
            chan.sender.send(Ok(proto::MessageOut::new_bcast(bcast)))?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            let mut p2p_msg_count = 1;
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    let (tofnd_idx, _) = map_tofn_to_tofnd_idx(i, party_share_counts)?;
                    protocol_info!(
                        "out p2p to [{}] ({}/{})",
                        party_uids[tofnd_idx],
                        p2p_msg_count,
                        p2ps.len() - 1
                    );
                    p2p_msg_count += 1;
                    chan.sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[tofnd_idx], &p2p)))?;
                }
            }
        }

        // collect incoming messages
        protocol_info!("waiting for incoming messages");
        let mut p2p_msg_count = 0;
        let mut bcast_msg_count = 0;
        while protocol.expecting_more_msgs_this_round() {
            let traffic = chan.receiver.recv().await.ok_or(format!(
                "{}: stream closed by client before protocol has completed",
                round
            ))?;
            if traffic.is_none() {
                warn!("ignore incoming msg: missing `data` field");
                continue;
            }
            let traffic = traffic.unwrap();

            // get the first and last share idx of sender
            let tofnd_idx = party_uids
                .iter()
                .position(|uid| *uid == traffic.from_party_uid)
                .unwrap();
            let share_count = party_share_counts[tofnd_idx];
            let first_tofn_idx = map_tofnd_to_tofn_idx(tofnd_idx, 0, party_share_counts);
            let last_tofn_idx = first_tofn_idx + share_count - 1; // range is inclusive, so we have to subtract one

            if traffic.is_broadcast {
                bcast_msg_count += 1;
                protocol_info!(
                    "got incoming bcast message {}/{}",
                    bcast_msg_count,
                    total_num_of_shares
                );
            } else {
                p2p_msg_count += 1;
                protocol_info!(
                    "got incoming p2p message {}/{}",
                    p2p_msg_count,
                    total_round_p2p_msgs
                );
            }

            // set message and declare sender's share indices
            protocol.set_msg_in(
                &traffic.payload,
                &IndexRange {
                    first: first_tofn_idx,
                    last: last_tofn_idx,
                },
            );
        }
        protocol_info!("got all {} incoming bcast messages", bcast_msg_count);
        protocol_info!("got all {} incoming p2p messages", p2p_msg_count);
        protocol_info!("end");
    }
    protocol_info!("end");
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
