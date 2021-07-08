//! This module handles the routing of incoming traffic.
//! Receives and validates a messages until validation fails, or the client closes

// universal error type
use crate::TofndError;

// tonic cruft
use super::proto;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::Status;

// logging
use tracing::{error, info, span, warn, Level, Span};

#[derive(Debug, PartialEq)]
enum RoutingResult {
    Continue { traffic: proto::TrafficIn },
    Stop,
    Skip,
}

fn validate_message(msg: Option<Result<proto::MessageIn, Status>>, span: Span) -> RoutingResult {
    // start routing span
    let route_span = span!(parent: &span, Level::INFO, "routing");
    let _start = route_span.enter();

    // we receive MessageIn under multiple leyers. We have to unpeel tonic message

    // get result
    let msg_result = match msg {
        Some(msg_result) => msg_result,
        None => {
            info!("Stream closed");
            return RoutingResult::Stop;
        }
    };

    // get data option
    let msg_data_opt = match msg_result {
        Ok(msg_in) => msg_in.data,
        Err(err) => {
            error!("Stream closed due to error {}", err);
            return RoutingResult::Stop;
        }
    };

    // get message data
    let msg_data = match msg_data_opt {
        Some(msg_data) => msg_data,
        None => {
            warn!("ignore incoming msg: missing `data` field");
            return RoutingResult::Skip;
        }
    };

    // match message data to types
    let traffic = match msg_data {
        proto::message_in::Data::Traffic(t) => t,
        proto::message_in::Data::Abort(_) => {
            warn!("received abort message");
            return RoutingResult::Stop;
        }
        _ => {
            warn!("ignore incoming msg: expect `data` to be TrafficIn type");
            return RoutingResult::Skip;
        }
    };

    // return traffic
    RoutingResult::Continue { traffic }
}

/// Receives incoming from a gRPC stream and vector of out going channels;
/// Loops until client closes the socket, or an `Abort` message is received  
/// Empty and unknown messages are ignored
pub(super) async fn route_messages(
    in_stream: &mut tonic::Streaming<proto::MessageIn>,
    mut out_channels: Vec<mpsc::UnboundedSender<Option<proto::TrafficIn>>>,
    span: Span,
) {
    // loop until `stop` is received
    loop {
        // read message from stream
        let msg_data = in_stream.next().await;

        // validate message
        let traffic = match validate_message(msg_data, span.clone()) {
            RoutingResult::Continue { traffic } => traffic,
            RoutingResult::Stop => break,
            RoutingResult::Skip => continue,
        };

        // send the message to all channels
        for out_channel in &mut out_channels {
            let _ = out_channel.send(Some(traffic.clone()));
        }
    }
}

/// Receives incoming from a gRPC stream and vector of out going channels;
/// Loops until client closes the socket, or an `Abort` message is received  
/// Empty and unknown messages are ignored
pub(super) async fn _route_messages_old(
    in_stream: &mut tonic::Streaming<proto::MessageIn>,
    mut out_channels: Vec<mpsc::UnboundedSender<Option<proto::TrafficIn>>>,
    span: Span,
) -> Result<(), TofndError> {
    loop {
        let msg_data = in_stream.next().await;

        let route_span = span!(parent: &span, Level::INFO, "routing");
        let start = route_span.enter();
        if msg_data.is_none() {
            info!("Stream closed");
            break;
        }
        let msg_data = msg_data.unwrap();

        // TODO: handle error if channel is closed prematurely.
        // The router needs to determine whether the protocol is completed.
        // In this case it should stop gracefully. If channel closes before the
        // protocol was completed, then we should throw an error.
        // Note: When axelar-core closes the channel at the end of the protocol, msg_data returns an error
        if msg_data.is_err() {
            info!("Stream closed");
            break;
        }

        let msg_data = msg_data.unwrap().data;

        // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
        if msg_data.is_none() {
            warn!("ignore incoming msg: missing `data` field");
            continue;
        }
        let traffic = match msg_data.unwrap() {
            proto::message_in::Data::Traffic(t) => t,
            proto::message_in::Data::Abort(_) => {
                warn!("received abort message");
                break;
            }
            _ => {
                warn!("ignore incoming msg: expect `data` to be TrafficIn type");
                continue;
            }
        };

        // need to drop span before entering async code or we have log conflicts
        // with protocol execution https://github.com/tokio-rs/tracing#in-asynchronous-code
        drop(start);

        // send the message to all of my shares. This applies to p2p and bcast messages.
        // We also broadcast p2p messages to facilitate fault attribution
        for out_channel in &mut out_channels {
            let _ = out_channel.send(Some(traffic.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        message_in: proto::MessageIn,
        expected_result: RoutingResult,
    }

    impl TestCase {
        fn new(message_in: proto::MessageIn, expected_result: RoutingResult) -> Self {
            TestCase {
                message_in,
                expected_result,
            }
        }
    }

    fn new_msg_in(msg_in: proto::message_in::Data) -> proto::MessageIn {
        proto::MessageIn { data: Some(msg_in) }
    }

    #[test]
    fn test_validate_message() {
        let test_cases = vec![
            TestCase::new(
                new_msg_in(proto::message_in::Data::Abort(true)),
                RoutingResult::Stop,
            ),
            TestCase::new(
                new_msg_in(proto::message_in::Data::KeygenInit(
                    proto::KeygenInit::default(),
                )),
                RoutingResult::Skip,
            ),
            TestCase::new(
                new_msg_in(proto::message_in::Data::SignInit(proto::SignInit::default())),
                RoutingResult::Skip,
            ),
            TestCase::new(
                new_msg_in(proto::message_in::Data::Traffic(proto::TrafficIn::default())),
                RoutingResult::Continue {
                    traffic: proto::TrafficIn::default(),
                },
            ),
            TestCase::new(proto::MessageIn { data: None }, RoutingResult::Skip),
        ];

        let span = span!(Level::INFO, "test-span");

        for test_case in test_cases {
            let result = validate_message(Some(Ok(test_case.message_in)), span.clone());
            assert_eq!(result, test_case.expected_result);
        }

        let result = validate_message(Some(Err(tonic::Status::ok("test status"))), span.clone());
        assert_eq!(result, RoutingResult::Stop);

        let result = validate_message(None, span.clone());
        assert_eq!(result, RoutingResult::Stop);
    }
}
