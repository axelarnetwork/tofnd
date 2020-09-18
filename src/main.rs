use tonic::{transport::Server, Request, Response, Status};

use tssd::gg20_server::{Gg20, Gg20Server};
use tssd::{
    KeygenRound1Request,
    KeygenRound1Response,
    KeygenRound2Request,
    KeygenRound2Response,
};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{Keys, SharedKeys};

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

pub mod tssd {
    tonic::include_proto!("tssd");
}

#[derive(Debug)]
enum KeygenStatus {
    Round1Done,
    // Round2Done,
    // Round3Done,
    // Round4Done,
}

// keygen state persisted to disk in the multi_party_ecdsa library
#[derive(Debug)]
struct MultiPartyEcdsaKeygenState {
    keys: Keys,
    // shared_keys: SharedKeys,
    // vss_scheme_vec: Vec<VerifiableSS>,
    // paillier_key_vec: Vec<EncryptionKey>,
    // y_sum: GE,
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

        // create new key material, get messages for rounds 1, 2
        let party_keys = Keys::create(0); // TODO we don't use party index
        let (bc_i, decom_i) =
            party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        // - return only the KeygenMessage1 part; save the decommitment for later

        // prepare response
        // TODO for now reply fields are merely strings
        let reply = tssd::KeygenRound1Response {
            commit: Some(tssd::Commit {
                paillier_encryption_key: format!("{:?}", bc_i.e),
                dlog_statement: format!("{:?}", bc_i.dlog_statement),
                commit: format!("{:?}", bc_i.com),
                correct_key_proof: format!("{:?}", bc_i.correct_key_proof),
                composite_dlog_proof: format!("{:?}", bc_i.composite_dlog_proof),
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
                        keys: party_keys,
                    },
                },
            );
        } // unlock state

        Ok(Response::new(reply))
    }

    async fn keygen_round2(
        &self,
        request: tonic::Request<KeygenRound2Request>,
    ) -> Result<tonic::Response<KeygenRound2Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let reply = tssd::KeygenRound2Response {
            vss_scheme: "foo".to_string(),
            secret_shares: "bar".to_string(),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let greeter = GG20Service::default();

    Server::builder()
        .add_service(Gg20Server::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}
