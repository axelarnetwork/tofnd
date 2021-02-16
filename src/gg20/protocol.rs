//! Abstract functionality used by keygen, sign, etc.
use tofn::protocol::Protocol;

use super::proto;
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;

pub(super) async fn execute_protocol(
    protocol: &mut impl Protocol,
    stream: &mut tonic::Streaming<proto::MessageIn>,
    msg_sender: &mut mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
) -> Result<(), TofndError> {
    // TODO runs an extra iteration!
    while !protocol.done() {
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            msg_sender
                .send(Ok(proto::MessageOut::new_bcast(bcast)))
                .await?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    msg_sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[i], p2p)))
                        .await?;
                }
            }
        }

        // collect incoming messages
        while protocol.expecting_more_msgs_this_round() {
            let msg_data = stream
                .next()
                .await
                .ok_or("stream closed by client before protocol has completed")??
                .data;
            // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
            if msg_data.is_none() {
                println!("WARN: ignore client message: missing `data` field");
                continue;
            }
            let traffic = match msg_data.unwrap() {
                proto::message_in::Data::Traffic(t) => t,
                _ => {
                    println!("WARN: ignore client message: expected `data` to be TrafficIn type");
                    continue;
                }
            };
            protocol.set_msg_in(&traffic.payload)?;
        }
    }
    Ok(())
}
