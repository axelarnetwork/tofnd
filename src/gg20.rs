use tonic::{transport::Server, Request, Response, Status};
use super::grpc as grpc;
use grpc::gg20_server::{Gg20, Gg20Server};
use grpc::{
    KeygenRound1Request,
    KeygenRound1Response,
    KeygenRound2Request,
    KeygenRound2Response,
    KeygenRound3Request,
    KeygenRound3Response,
};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    Keys,
    SharedKeys,
    KeyGenBroadcastMessage1,
    KeyGenDecommitMessage1,
};

// inherited from multi-party-ecdsa
use curv::{
    // arithmetic::traits::Converter,
    cryptographic_primitives::{
        // proofs::sigma_dlog::DLogProof,
        secret_sharing::feldman_vss::VerifiableSS,
    },
    // elliptic::curves::traits::{ECPoint, ECScalar},
    // BigInt, FE, GE,
    GE,
};
use paillier::EncryptionKey;

#[derive(Debug, PartialEq)]
enum KeygenStatus {
    Round1Done,
    Round2Done,
    // Round3Done,
    // Round4Done,
}

// keygen state persisted to disk in the multi-party-ecdsa library
// TODO there's probably lots of duplication here; multi-party-ecdsa is a mess
#[derive(Debug)]
struct MultiPartyEcdsaKeygenState {
    my_keys: Keys,
    // shared_keys: SharedKeys,
    // vss_scheme_vec: Vec<VerifiableSS>,
    // paillier_key_vec: Vec<EncryptionKey>,
    // y_sum: GE,
    my_commit: KeyGenBroadcastMessage1,
    my_reveal: KeyGenDecommitMessage1,
    // other_commits: Vec<KeyGenBroadcastMessage1>,
    // other_reveals: Vec<KeyGenDecommitMessage1>,
}

#[derive(Debug)]
struct KeygenSessionState {
    status: KeygenStatus,
    state: MultiPartyEcdsaKeygenState,
}

#[derive(Debug, Default)]
pub struct GG20Service {
    // TODO for now be conservative wrt thread safety
    // see https://tokio.rs/tokio/tutorial/shared-state
    keygen_sessions: Arc<Mutex<HashMap<Uuid, KeygenSessionState>>>,
}

#[tonic::async_trait]
impl Gg20 for GG20Service {
    async fn keygen_round1(
        &self,
        request: Request<KeygenRound1Request>,
    ) -> Result<Response<KeygenRound1Response>, Status> {
        println!("Got a request: {:?}", request);

        // do as much work as possible before locking self.keygen_sessions
        // TODO inserting a new session requires a lock on the whole HashMap
        //   by contrast, updating an existing session requires only a lock on that portion of the HashMap
        //   should we split session creation into another (faster) gRPC call?

        // TODO for now, uuids are just strings
        let session_id = Uuid::parse_str(
            &request.into_inner().session_id.unwrap().value
        ).unwrap();

        // create new key material, get responses for rounds 1, 2
        let my_keys = Keys::create(0); // TODO we don't use party index
        let (my_commit, my_reveal) =
            my_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        // prepare response
        // TODO for now reply fields are merely strings
        let reply = grpc::KeygenRound1Response {
            commit: Some(grpc::Commit {
                paillier_encryption_key: format!("{:?}", my_commit.e),
                dlog_statement: format!("{:?}", my_commit.dlog_statement),
                value: format!("{:?}", my_commit.com),
                correct_key_proof: format!("{:?}", my_commit.correct_key_proof),
                composite_dlog_proof: format!("{:?}", my_commit.composite_dlog_proof),
            }),
        };

        { // lock state
            let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

            // session_id should be brand new
            if keygen_sessions.contains_key(&session_id) {
                return Err(Status::already_exists(format!(
                    "KeygenSessionId {:?} already exists",
                    session_id
                )));
            }

            // save state
            // TODO save state from decom_i
            keygen_sessions.insert(
                session_id,
                KeygenSessionState {
                    status: KeygenStatus::Round1Done,
                    state: MultiPartyEcdsaKeygenState {
                        my_keys: my_keys,
                        my_commit: my_commit,
                        my_reveal: my_reveal,
                    },
                },
            );
        } // unlock state

        Ok(Response::new(reply))
    }

    async fn keygen_round2(
        &self,
        request: Request<KeygenRound2Request>,
    ) -> Result<Response<KeygenRound2Response>, Status> {
        println!("Got a request: {:?}", request);

        let session_id = Uuid::parse_str(
            &request.get_ref().session_id.as_ref().unwrap().value
        ).unwrap();

        let num_parties = request.get_ref().commits.len();
        if num_parties < 2 {
            return Err(Status::invalid_argument(format!("not enough parties: {:?}", num_parties)));
        }

        // session_id should exist and be in state Round1Done
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();
        let mut keygen_session = match keygen_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => {return Err(Status::not_found(format!("KeygenSessionId {:?} not found", session_id)))},
        };
        if keygen_session.status != KeygenStatus::Round1Done {
            return Err(Status::failed_precondition(format!("incorrect status for KeygenSessionId {:?}", session_id)));
        }
        keygen_session.status = KeygenStatus::Round2Done;

        let commits = &request.get_ref().commits;
        // convert commits and copy into keygen_session.state.other_commits

        let reply = grpc::KeygenRound2Response {
            reveal: Some(grpc::Reveal {
                blind_factor: "Rick".to_string(),
                pk_share: "Morty".to_string(),
            }),
        };
        Ok(Response::new(reply))
    }

    async fn keygen_round3(
        &self,
        request: tonic::Request<KeygenRound3Request>,
    ) -> Result<tonic::Response<KeygenRound3Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let session_id = Uuid::parse_str(
            &request.into_inner().session_id.unwrap().value
        ).unwrap();
        
        let reply = grpc::KeygenRound3Response {
            vss_scheme: "foo".to_string(),
            secret_shares: "bar".to_string(),
        };
        Ok(Response::new(reply))
    }
}