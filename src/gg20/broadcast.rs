//! This module handles the routing of incoming traffic.
//! Receives and validates messages until the connection is closed by the client.
//! The incoming messages come from the gRPC stream and are forwarded to shares' internal channels.

// tonic cruft
use super::proto;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::Status;

// logging
use tracing::{error, info, span, warn, Level, Span};

/// Results of routing
#[derive(Debug, PartialEq)]
enum RoutingStatus {
    Continue { traffic: proto::TrafficIn },
    Stop,
    Skip,
}

/// Receives incoming from a gRPC stream and broadcasts them to internal channels;
/// Loops until client closes the socket, or a message containing [proto::message_in::Data::Abort] is received  
/// Empty and unknown messages are ignored
pub(super) async fn broadcast_messages(
    in_grpc_stream: &mut tonic::Streaming<proto::MessageIn>,
    mut out_internal_channels: Vec<mpsc::UnboundedSender<Option<proto::TrafficIn>>>,
    span: Span,
) {
    // loop until `stop` is received
    loop {
        // read message from stream
        let msg_data = in_grpc_stream.next().await;

        // check incoming message
        let traffic = match open_message(msg_data, span.clone()) {
            RoutingStatus::Continue { traffic } => traffic,
            RoutingStatus::Stop => break,
            RoutingStatus::Skip => continue,
        };

        // send the message to all channels
        for out_channel in &mut out_internal_channels {
            let _ = out_channel.send(Some(traffic.clone()));
        }
    }
}

/// gets a gPRC [proto::MessageIn] and checks the type
/// available messages are:
/// [proto::message_in::Data::Traffic]    -> return [RoutingResult::Continue]
/// [proto::message_in::Data::Abort]      -> return [RoutingResult::Stop]
/// [proto::message_in::Data::KeygenInit] -> return [RoutingResult::Skip]
/// [proto::message_in::Data::SignInit]   -> return [RoutingResult::Skip]
fn open_message(msg: Option<Result<proto::MessageIn, Status>>, span: Span) -> RoutingStatus {
    // start routing span
    let route_span = span!(parent: &span, Level::INFO, "routing");
    let _start = route_span.enter();

    // we receive MessageIn wrapped in multiple layers. We have to unpeel tonic message

    // get result
    let msg_result = match msg {
        Some(msg_result) => msg_result,
        None => {
            info!("Stream closed");
            return RoutingStatus::Stop;
        }
    };

    // get data option
    let msg_data_opt = match msg_result {
        Ok(msg_in) => msg_in.data,
        Err(err) => {
            error!("Stream closed due to error {}", err);
            return RoutingStatus::Stop;
        }
    };

    // get message data
    let msg_data = match msg_data_opt {
        Some(msg_data) => msg_data,
        None => {
            warn!("ignore incoming msg: missing `data` field");
            return RoutingStatus::Skip;
        }
    };

    // match message data to types
    let traffic = match msg_data {
        proto::message_in::Data::Traffic(t) => t,
        proto::message_in::Data::Abort(_) => {
            warn!("received abort message");
            return RoutingStatus::Stop;
        }
        proto::message_in::Data::KeygenInit(_) | proto::message_in::Data::SignInit(_) => {
            warn!("ignore incoming msg: expect `data` to be TrafficIn type");
            return RoutingStatus::Skip;
        }
    };

    // return traffic
    RoutingStatus::Continue { traffic }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        message_in: proto::MessageIn,
        expected_result: RoutingStatus,
    }

    impl TestCase {
        fn new(message_in: proto::MessageIn, expected_result: RoutingStatus) -> Self {
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
                RoutingStatus::Stop,
            ),
            TestCase::new(
                new_msg_in(proto::message_in::Data::KeygenInit(
                    proto::KeygenInit::default(),
                )),
                RoutingStatus::Skip,
            ),
            TestCase::new(
                new_msg_in(proto::message_in::Data::SignInit(proto::SignInit::default())),
                RoutingStatus::Skip,
            ),
            TestCase::new(
                new_msg_in(proto::message_in::Data::Traffic(proto::TrafficIn::default())),
                RoutingStatus::Continue {
                    traffic: proto::TrafficIn::default(),
                },
            ),
            TestCase::new(proto::MessageIn { data: None }, RoutingStatus::Skip),
        ];

        let span = span!(Level::INFO, "test-span");

        for test_case in test_cases {
            let result = open_message(Some(Ok(test_case.message_in)), span.clone());
            assert_eq!(result, test_case.expected_result);
        }

        let result = open_message(Some(Err(tonic::Status::ok("test status"))), span.clone());
        assert_eq!(result, RoutingStatus::Stop);

        let result = open_message(None, span);
        assert_eq!(result, RoutingStatus::Stop);
    }
}
