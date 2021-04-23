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
            let protocol_span = span!(parent: &span, Level::INFO, "", round);
            // enter span
            let _start = protocol_span.enter();
            // log message
            info!($e $(, $opt)*);
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
            protocol_info!("out bcast");
            chan.sender.send(Ok(proto::MessageOut::new_bcast(bcast)))?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    let (tofnd_idx, _) =
                        map_tofn_to_tofnd_idx(party_indices[i], party_share_counts)?;
                    protocol_info!("out p2p to [{}]", party_uids[tofnd_idx]);
                    chan.sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[tofnd_idx], &p2p)))?;
                }
            }
        }

        // collect incoming messages
        protocol_info!("wait for incoming messages");
        while protocol.expecting_more_msgs_this_round() {
            let traffic = chan.receiver.next().await.ok_or(format!(
                "{}: stream closed by client before protocol has completed",
                round
            ))?;
            if traffic.is_none() {
                warn!("ignore incoming msg: missing `data` field");
                continue;
            }
            let traffic = traffic.unwrap();
            protocol.set_msg_in(&traffic.payload)?;
        }
        protocol_info!("got all incoming messages");
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
