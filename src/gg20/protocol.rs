//! Abstract functionality used by keygen, sign, etc.
use tofn::protocol::Protocol;

use super::proto;
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;

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
