use tonic;
// Go-style usage idiom:
// prefer `use tonic;` to `use tonic::Request;`
// so that we write `tonic::Request` instead of `Request`

use super::grpc as grpc;
// use grpc::gg20_server::{Gg20, Gg20Server};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use bincode;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i as zengo;
// use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
//     Keys,
//     SharedKeys,
//     KeyGenBroadcastMessage1,
//     KeyGenDecommitMessage1,
// };

// inherited from multi-party-ecdsa
// use curv::{
//     arithmetic::traits::Converter,
//     cryptographic_primitives::{
//         proofs::sigma_dlog::DLogProof,
//         secret_sharing::feldman_vss::VerifiableSS,
//     },
//     elliptic::curves::traits::{ECPoint, ECScalar},
//     BigInt, FE, GE,
//     GE,
// };
// use paillier::EncryptionKey;

#[derive(Debug, PartialEq)]
enum KeygenStatus {
    Round1Done,
    Round2Done,
    Round3Done,
    // Round4Done,
}

// keygen state persisted to disk in the multi-party-ecdsa library
// TODO there's probably lots of duplication here; multi-party-ecdsa is a mess
#[derive(Debug)]
struct ZengoState {
    my_keys: zengo::Keys,
    // shared_keys: SharedKeys,
    // vss_scheme_vec: Vec<VerifiableSS>,
    // paillier_key_vec: Vec<EncryptionKey>,
    // y_sum: GE,
    // my_commit: zengo::KeyGenBroadcastMessage1,
    // my_reveal: zengo::KeyGenDecommitMessage1,
    commits: Vec<zengo::KeyGenBroadcastMessage1>, // mine is first
    reveals: Vec<zengo::KeyGenDecommitMessage1>, // mine is first
}

#[derive(Debug)]
struct KeygenSessionState {
    status: KeygenStatus,
    state: ZengoState,
}

#[derive(Debug, Default)]
pub struct GG20Service {
    // TODO for now be conservative wrt thread safety
    // see https://tokio.rs/tokio/tutorial/shared-state
    keygen_sessions: Arc<Mutex<HashMap<Uuid, KeygenSessionState>>>,
}

#[tonic::async_trait]
impl grpc::gg20_server::Gg20 for GG20Service {
    async fn keygen_round1(
        &self,
        request: tonic::Request<grpc::KeygenRound1Request>,
    ) -> Result<tonic::Response<grpc::KeygenRound1Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        // do as much work as possible before locking self.keygen_sessions
        // TODO inserting a new session requires a lock on the whole HashMap
        //   by contrast, updating an existing session requires only a lock on that portion of the HashMap
        //   should we split session creation into another (faster) gRPC call?

        let session_id = Uuid::parse_str(&request.get_ref().session_id).unwrap(); // string
        // let session_id = Uuid::from_slice( &request.get_ref().session_id ).unwrap(); // bytes

        // create new key material, get responses for rounds 1, 2
        let my_keys = zengo::Keys::create(0); // we don't use party index
        // TODO use create_safe_prime in production
        // let my_keys = zengo::Keys::create_safe_prime(0);
        let (my_commit, my_reveal) =
            my_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        let response = grpc::KeygenRound1Response {
            my_commit: bincode::serialize(&my_commit).unwrap(),
        };

        // lock state
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

        // session_id should be brand new
        if keygen_sessions.contains_key(&session_id) {
            return Err(tonic::Status::already_exists(format!(
                "session_id {:?} already exists",
                session_id
            )));
        }

        // save state
        keygen_sessions.insert(
            session_id,
            KeygenSessionState {
                status: KeygenStatus::Round1Done,
                state: ZengoState {
                    my_keys: my_keys,
                    commits: vec![my_commit], // mine is first
                    reveals: vec![my_reveal], // mine is first
                },
            },
        );

        Ok(tonic::Response::new(response))
    }

    async fn keygen_round2(
        &self,
        request: tonic::Request<grpc::KeygenRound2Request>,
    ) -> Result<tonic::Response<grpc::KeygenRound2Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let session_id = Uuid::parse_str(&request.get_ref().session_id).unwrap(); // string
        // let session_id = Uuid::from_slice( &request.get_ref().session_id ).unwrap(); // bytes

        // deserialize request_commits
        let request_commits = &request.get_ref().other_commits;
        if request_commits.len() < 1 {
            return Err(tonic::Status::invalid_argument(format!("not enough other parties: {:?}", request_commits.len())));
        }
        // TODO there should be a way to do this using unwrap_or_else
        // let other_commits : Vec<zengo::KeyGenBroadcastMessage1> = request_commits.iter().map(|c| bincode::deserialize(&c).unwrap()).collect::<Vec<_>>();
        let mut other_commits : Vec<zengo::KeyGenBroadcastMessage1> = Vec::with_capacity(request_commits.len());
        for request_commit in request_commits.iter() {
            other_commits.push(
                match bincode::deserialize(request_commit) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(tonic::Status::invalid_argument(format!("deserialization failure for other_commits: {:?}", e)));
                    }
                }
            );
        }

        // TODO the number and order of parties is dictated by whatever we find in request_commits
        // it's the responsibility of the caller to maintain this order in subsequent rounds

        // lock state
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

        // session_id should exist and be in state Round1Done
        let mut keygen_session = match keygen_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => {return Err(tonic::Status::not_found(format!("session_id {:?} not found", session_id)))},
        };
        if keygen_session.status != KeygenStatus::Round1Done {
            return Err(tonic::Status::failed_precondition(format!("incorrect status for session_id {:?}", session_id)));
        }

        let response = grpc::KeygenRound2Response {
            my_reveal: bincode::serialize(&keygen_session.state.reveals[0]).unwrap(),
        };

        keygen_session.state.commits.append(&mut other_commits);
        keygen_session.status = KeygenStatus::Round2Done;

        Ok(tonic::Response::new(response))
    }

    async fn keygen_round3(
        &self,
        request: tonic::Request<grpc::KeygenRound3Request>,
    ) -> Result<tonic::Response<grpc::KeygenRound3Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let session_id = Uuid::parse_str(&request.get_ref().session_id).unwrap(); // string
        // let session_id = Uuid::from_slice( &request.get_ref().session_id ).unwrap(); // bytes
        
        // deserialize request_reveals
        // TODO repeated code from keygen_round2
        let request_reveals = &request.get_ref().other_reveals;
        if request_reveals.len() < 1 {
            return Err(tonic::Status::invalid_argument(format!("not enough other parties: {:?}", request_reveals.len())));
        }
        let mut other_reveals : Vec<zengo::KeyGenDecommitMessage1> = Vec::with_capacity(request_reveals.len());
        for request_reveal in request_reveals.iter() {
            other_reveals.push(
                match bincode::deserialize(request_reveal) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(tonic::Status::invalid_argument(format!("deserialization failure for other_reveals: {:?}", e)));
                    }
                }
            );
        }

        // get secret shares

        // encrypt secret shares

        // lock state
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

        // session_id should exist and be in state Round2Done
        let mut keygen_session = match keygen_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => {return Err(tonic::Status::not_found(format!("session_id {:?} not found", session_id)))},
        };
        if keygen_session.status != KeygenStatus::Round2Done {
            return Err(tonic::Status::failed_precondition(format!("incorrect status for session_id {:?}", session_id)));
        }

        let response = grpc::KeygenRound3Response {
            encrypted_secret_shares: Vec::default(), // bincode::serialize(&keygen_session.state.my_reveal).unwrap(),
        };

        keygen_session.state.reveals.append(&mut other_reveals);
        keygen_session.status = KeygenStatus::Round3Done;

        Ok(tonic::Response::new(response))
    }
}